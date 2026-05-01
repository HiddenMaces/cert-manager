import os
import shutil
import datetime
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from dotenv import load_dotenv

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

CERT_DIR = os.getenv('CERT_DIR', './certs')
ROOT_DIR = os.getenv('ROOT_DIR', './rootCA')
ROOT_CA_NAME = os.getenv('ROOT_CA_NAME', 'rootca')

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(ROOT_DIR, exist_ok=True)


# --- Helpers ---

def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def load_key(path, password=None):
    with open(path, "rb") as f:
        pwd_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(f.read(), password=pwd_bytes)

def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_csr(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())

def cert_not_after(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

def cert_not_before(cert):
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

def get_sans_from_ext_content(content):
    sans = []
    for line in content.splitlines():
        line = line.strip()
        if line.upper().startswith("DNS"):
            parts = line.split('=', 1)
            if len(parts) > 1:
                sans.append(x509.DNSName(parts[1].strip()))
        elif line.upper().startswith("IP"):
            parts = line.split('=', 1)
            if len(parts) > 1:
                try:
                    sans.append(x509.IPAddress(ipaddress.ip_address(parts[1].strip())))
                except ValueError:
                    pass
        elif line.upper().startswith("EMAIL"):
            parts = line.split('=', 1)
            if len(parts) > 1:
                sans.append(x509.RFC822Name(parts[1].strip()))
    return sans

def get_cert_type(cert_dir):
    type_file = os.path.join(cert_dir, 'cert.type')
    if os.path.exists(type_file):
        with open(type_file, 'r') as f:
            return f.read().strip()
    return 'server'

def parse_cert_details(crt_path):
    try:
        cert = load_cert(crt_path)
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = cert_not_after(cert)
        not_before = cert_not_before(cert)
        days_left = (not_after - now).days

        subject_cn = next(
            (a.value for a in cert.subject if a.oid == NameOID.COMMON_NAME), ''
        )
        issuer_cn = next(
            (a.value for a in cert.issuer if a.oid == NameOID.COMMON_NAME), ''
        )

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    sans.append(f"DNS: {san.value}")
                elif isinstance(san, x509.IPAddress):
                    sans.append(f"IP: {san.value}")
                elif isinstance(san, x509.RFC822Name):
                    sans.append(f"email: {san.value}")
        except x509.ExtensionNotFound:
            pass

        eku = []
        try:
            eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            for usage in eku_ext.value:
                if usage == ExtendedKeyUsageOID.SERVER_AUTH:
                    eku.append('serverAuth')
                elif usage == ExtendedKeyUsageOID.CLIENT_AUTH:
                    eku.append('clientAuth')
        except x509.ExtensionNotFound:
            pass

        return {
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'not_before': not_before.strftime('%Y-%m-%d %H:%M UTC'),
            'not_after': not_after.strftime('%Y-%m-%d %H:%M UTC'),
            'days_left': days_left,
            'serial': format(cert.serial_number, 'X'),
            'sans': sans,
            'eku': eku,
        }
    except Exception:
        return None

def _build_cert(csr, issuer_name, issuer_public_key, signing_key, days, cert_type, ext_path):
    is_client = cert_type == 'client'

    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=not is_client,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    eku_oid = ExtendedKeyUsageOID.CLIENT_AUTH if is_client else ExtendedKeyUsageOID.SERVER_AUTH

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku_oid]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
    )

    if os.path.exists(ext_path):
        with open(ext_path, 'r') as f:
            content = f.read()
        sans = get_sans_from_ext_content(content)
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans), critical=False
            )

    return builder.sign(signing_key, hashes.SHA256())


# --- Routes ---

@app.route('/')
def home_redirect():
    return redirect(url_for('index'))

@app.route('/cert/')
def index():
    cert_dirs = sorted(
        d for d in os.listdir(CERT_DIR) if os.path.isdir(os.path.join(CERT_DIR, d))
    )

    root_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    root_exists = os.path.exists(root_crt_path)
    root_subject = None
    root_info = None

    if root_exists:
        try:
            root_cert = load_cert(root_crt_path)
            root_subject = root_cert.subject
            now = datetime.datetime.now(datetime.timezone.utc)
            not_after = cert_not_after(root_cert)
            cn_attrs = root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            root_info = {
                'cn': cn_attrs[0].value if cn_attrs else ROOT_CA_NAME,
                'not_after': not_after.strftime('%Y-%m-%d'),
                'days_left': (not_after - now).days,
            }
        except Exception:
            pass

    analyzed_certs = []
    for fqdn in cert_dirs:
        cert_dir = os.path.join(CERT_DIR, fqdn)
        crt_path = os.path.join(cert_dir, f"{fqdn}.crt")
        status = "pending"
        not_after_str = None
        days_left = None
        cert_type = get_cert_type(cert_dir)

        if os.path.exists(crt_path):
            try:
                cert_obj = load_cert(crt_path)
                now = datetime.datetime.now(datetime.timezone.utc)
                not_after = cert_not_after(cert_obj)
                days_left = (not_after - now).days
                not_after_str = not_after.strftime('%Y-%m-%d')

                if cert_obj.issuer == cert_obj.subject:
                    status = "blue"
                elif root_subject and cert_obj.issuer == root_subject:
                    status = "green"
                else:
                    status = "red"
            except Exception:
                status = "error"

        analyzed_certs.append({
            'fqdn': fqdn,
            'status': status,
            'cert_type': cert_type,
            'not_after': not_after_str,
            'days_left': days_left,
        })

    return render_template('index.html',
                           certs=analyzed_certs,
                           root_exists=root_exists,
                           root_filename=f"{ROOT_CA_NAME}.crt",
                           root_info=root_info)

@app.route('/cert/download_root')
def download_root():
    return send_from_directory(ROOT_DIR, f"{ROOT_CA_NAME}.crt", as_attachment=True)

@app.route('/cert/download/<fqdn>/<filetype>')
def download_cert_file(fqdn, filetype):
    allowed = {'crt', 'key', 'csr', 'p12'}
    if filetype not in allowed:
        flash('Invalid file type.', 'error')
        return redirect(url_for('manage_cert', fqdn=fqdn))

    cert_dir = os.path.join(CERT_DIR, fqdn)
    filename = f"{fqdn}.{filetype}"
    file_path = os.path.join(cert_dir, filename)

    if not os.path.exists(file_path):
        flash(f'{filetype.upper()} file not found.', 'error')
        return redirect(url_for('manage_cert', fqdn=fqdn))

    return send_from_directory(cert_dir, filename, as_attachment=True)

@app.route('/cert/create_root', methods=['GET', 'POST'])
def create_root():
    if request.method == 'GET':
        return render_template('create_root.html', prefill_cn=request.args.get('cn', ''))

    cn = request.form.get('cn', 'My Internal Root CA').strip()
    c = request.form.get('c', 'NL').strip()
    days = int(request.form.get('days', '3650'))
    email = request.form.get('email', '').strip()
    org = request.form.get('org', '').strip()
    org_unit = request.form.get('org_unit', '').strip()
    st = request.form.get('st', '').strip()
    city = request.form.get('city', '').strip()
    password = request.form.get('password', '').strip()

    key_file = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")
    crt_file = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")

    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        algorithm = (
            serialization.BestAvailableEncryption(password.encode('utf-8'))
            if password else serialization.NoEncryption()
        )
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=algorithm,
            ))

        name_attrs = [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, c),
        ]
        if st:       name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
        if city:     name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
        if org:      name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        if org_unit: name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
        if email:    name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        subject = x509.Name(name_attrs)

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )
        save_cert(cert, crt_file)
        flash('Root CA created successfully.', 'success')

    except Exception as e:
        flash(f'Error creating Root CA: {str(e)}', 'error')

    return redirect(url_for('index'))

@app.route('/cert/create', methods=['GET', 'POST'])
def create_cert():
    if request.method == 'POST':
        fqdn = request.form['fqdn'].strip()
        c = request.form.get('c', 'NL').strip()
        o = request.form.get('o', 'Hiddenmaces.nl').strip()
        ou = request.form.get('ou', 'IT').strip()
        cert_type = request.form.get('cert_type', 'server')
        if cert_type not in ('server', 'client'):
            cert_type = 'server'

        if not fqdn:
            flash("FQDN is required", "error")
            return redirect(url_for('create_cert'))

        cert_dir = os.path.join(CERT_DIR, fqdn)
        if os.path.exists(cert_dir):
            flash(f'Certificate for {fqdn} already exists.', 'error')
            return redirect(url_for('create_cert'))

        os.makedirs(cert_dir)

        try:
            with open(os.path.join(cert_dir, 'cert.type'), 'w') as f:
                f.write(cert_type)

            if cert_type == 'client':
                ext_content = (
                    "authorityKeyIdentifier=keyid,issuer\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage = digitalSignature\n"
                    "extendedKeyUsage = clientAuth\n"
                    "subjectAltName = @alt_names\n"
                    "\n[alt_names]\n"
                    f"email.1 = {fqdn}\n"
                )
            else:
                ext_content = (
                    "authorityKeyIdentifier=keyid,issuer\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n"
                    "extendedKeyUsage = serverAuth\n"
                    "subjectAltName = @alt_names\n"
                    "\n[alt_names]\n"
                    f"DNS.1 = {fqdn}\n"
                )

            with open(os.path.join(cert_dir, f"{fqdn}.v3.ext"), 'w') as f:
                f.write(ext_content)

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            save_key(private_key, os.path.join(cert_dir, f"{fqdn}.key"))

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, c),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
                x509.NameAttribute(NameOID.COMMON_NAME, fqdn),
            ])
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .sign(private_key, hashes.SHA256())
            )
            with open(os.path.join(cert_dir, f"{fqdn}.csr"), "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

            label = "Client" if cert_type == "client" else "Server"
            flash(f'{label} CSR and key created for {fqdn}. Please sign it now.', 'success')
            return redirect(url_for('manage_cert', fqdn=fqdn))

        except Exception as e:
            shutil.rmtree(cert_dir, ignore_errors=True)
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/cert/manage/<fqdn>')
def manage_cert(fqdn):
    cert_dir = os.path.join(CERT_DIR, fqdn)

    if not os.path.exists(cert_dir):
        flash(f"Certificate {fqdn} not found.", "error")
        return redirect(url_for('index'))

    ext_file = os.path.join(cert_dir, f"{fqdn}.v3.ext")
    csr_file = os.path.join(cert_dir, f"{fqdn}.csr")
    crt_file = os.path.join(cert_dir, f"{fqdn}.crt")

    ext_content = ""
    if os.path.exists(ext_file):
        with open(ext_file, 'r') as f:
            ext_content = f.read()

    has_crt = os.path.exists(crt_file)
    has_p12 = os.path.exists(os.path.join(cert_dir, f"{fqdn}.p12"))
    has_key = os.path.exists(os.path.join(cert_dir, f"{fqdn}.key"))
    has_csr = os.path.exists(csr_file)

    csr_details = {'cn': fqdn, 'c': '', 'o': '', 'ou': ''}
    if has_csr:
        try:
            csr = load_csr(csr_file)
            for attr in csr.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    csr_details['cn'] = attr.value
                elif attr.oid == NameOID.COUNTRY_NAME:
                    csr_details['c'] = attr.value
                elif attr.oid == NameOID.ORGANIZATION_NAME:
                    csr_details['o'] = attr.value
                elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                    csr_details['ou'] = attr.value
        except Exception:
            pass

    cert_type = get_cert_type(cert_dir)
    cert_details = parse_cert_details(crt_file) if has_crt else None

    return render_template('manage.html',
                           fqdn=fqdn,
                           ext_content=ext_content,
                           has_crt=has_crt,
                           has_p12=has_p12,
                           has_key=has_key,
                           has_csr=has_csr,
                           csr=csr_details,
                           cert_type=cert_type,
                           cert_details=cert_details)

@app.route('/cert/update_details/<fqdn>', methods=['POST'])
def update_details(fqdn):
    new_cn = request.form.get('cn', '').strip()
    c = request.form.get('c', '').strip()
    o = request.form.get('o', '').strip()
    ou = request.form.get('ou', '').strip()

    if not new_cn:
        flash("Common Name (FQDN) is required.", "error")
        return redirect(url_for('manage_cert', fqdn=fqdn))

    cert_dir = os.path.join(CERT_DIR, fqdn)
    key_path = os.path.join(cert_dir, f"{fqdn}.key")

    if not os.path.exists(key_path):
        flash("Private key not found. Cannot regenerate CSR.", "error")
        return redirect(url_for('manage_cert', fqdn=fqdn))

    try:
        private_key = load_key(key_path)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, c),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, new_cn),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256())
        )

        if new_cn == fqdn:
            with open(os.path.join(cert_dir, f"{fqdn}.csr"), "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
            flash("Certificate details updated (CSR regenerated).", "success")
            return redirect(url_for('manage_cert', fqdn=fqdn))

        new_cert_dir = os.path.join(CERT_DIR, new_cn)
        if os.path.exists(new_cert_dir):
            flash(f"Destination {new_cn} already exists.", "error")
            return redirect(url_for('manage_cert', fqdn=fqdn))

        with open(os.path.join(cert_dir, f"{fqdn}.csr"), "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        ext_path = os.path.join(cert_dir, f"{fqdn}.v3.ext")
        if os.path.exists(ext_path):
            with open(ext_path, 'r') as f:
                content = f.read()
            content = content.replace(f"DNS.1 = {fqdn}", f"DNS.1 = {new_cn}")
            with open(ext_path, 'w') as f:
                f.write(content)

        for ext in ['.key', '.csr', '.crt', '.v3.ext', '.p12']:
            old_f = os.path.join(cert_dir, f"{fqdn}{ext}")
            if os.path.exists(old_f):
                os.rename(old_f, os.path.join(cert_dir, f"{new_cn}{ext}"))

        os.rename(cert_dir, new_cert_dir)
        flash(f"Details updated and renamed to {new_cn}.", "success")
        return redirect(url_for('manage_cert', fqdn=new_cn))

    except Exception as e:
        flash(f"Error updating details: {str(e)}", "error")
        return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/update_ext/<fqdn>', methods=['POST'])
def update_ext(fqdn):
    content = request.form['ext_content']
    ext_file = os.path.join(CERT_DIR, fqdn, f"{fqdn}.v3.ext")
    with open(ext_file, 'w') as f:
        f.write(content)
    flash('Extension file updated.', 'success')
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/sign_root/<fqdn>', methods=['POST'])
def sign_root(fqdn):
    password = request.form.get('password')
    days = int(request.form.get('days', '365'))

    cert_dir = os.path.join(CERT_DIR, fqdn)
    csr_path = os.path.join(cert_dir, f"{fqdn}.csr")
    crt_path = os.path.join(cert_dir, f"{fqdn}.crt")
    ext_path = os.path.join(cert_dir, f"{fqdn}.v3.ext")

    ca_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    ca_key_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")

    try:
        csr = load_csr(csr_path)
        ca_cert = load_cert(ca_crt_path)
        ca_key = load_key(ca_key_path, password=password)
        cert_type = get_cert_type(cert_dir)

        cert = _build_cert(
            csr, ca_cert.subject, ca_key.public_key(), ca_key, days, cert_type, ext_path
        )
        save_cert(cert, crt_path)
        flash('Signed by Root CA successfully.', 'success')

    except ValueError:
        flash('Incorrect password for Root CA key.', 'error')
    except Exception as e:
        flash(f'Signing failed: {str(e)}', 'error')

    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/sign_self/<fqdn>', methods=['POST'])
def sign_self(fqdn):
    days = int(request.form.get('days', '365'))
    cert_dir = os.path.join(CERT_DIR, fqdn)
    csr_path = os.path.join(cert_dir, f"{fqdn}.csr")
    key_path = os.path.join(cert_dir, f"{fqdn}.key")
    crt_path = os.path.join(cert_dir, f"{fqdn}.crt")
    ext_path = os.path.join(cert_dir, f"{fqdn}.v3.ext")

    try:
        csr = load_csr(csr_path)
        private_key = load_key(key_path)
        cert_type = get_cert_type(cert_dir)

        cert = _build_cert(
            csr, csr.subject, private_key.public_key(), private_key, days, cert_type, ext_path
        )
        save_cert(cert, crt_path)
        flash('Self-signed successfully.', 'success')

    except Exception as e:
        flash(f'Signing failed: {str(e)}', 'error')

    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/create_p12/<fqdn>', methods=['POST'])
def create_p12(fqdn):
    password = request.form.get('password', '')
    cert_dir = os.path.join(CERT_DIR, fqdn)
    key_path = os.path.join(cert_dir, f"{fqdn}.key")
    crt_path = os.path.join(cert_dir, f"{fqdn}.crt")
    p12_path = os.path.join(cert_dir, f"{fqdn}.p12")

    try:
        private_key = load_key(key_path)
        cert = load_cert(crt_path)

        ca_certs = None
        ca_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
        if os.path.exists(ca_crt_path):
            try:
                ca_cert = load_cert(ca_crt_path)
                if cert.issuer == ca_cert.subject:
                    ca_certs = [ca_cert]
            except Exception:
                pass

        p12 = pkcs12.serialize_key_and_certificates(
            name=fqdn.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
        )
        with open(p12_path, "wb") as f:
            f.write(p12)

        flash('P12 container created successfully.', 'success')

    except Exception as e:
        flash(f'P12 creation failed: {str(e)}', 'error')

    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/delete/<fqdn>', methods=['POST'])
def delete_cert(fqdn):
    cert_dir = os.path.join(CERT_DIR, fqdn)
    try:
        shutil.rmtree(cert_dir)
        flash(f'Certificate {fqdn} deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting: {str(e)}', 'error')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
