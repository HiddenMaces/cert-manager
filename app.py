import os
import shutil
import datetime
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from dotenv import load_dotenv

# Cryptography imports
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

# Ensure dirs exist
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(ROOT_DIR, exist_ok=True)

# --- Helper Functions ---

def save_key(key, path):
    """Saves a private key to disk."""
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def load_key(path, password=None):
    """Loads a private key from disk."""
    with open(path, "rb") as f:
        # Encode password to bytes if provided
        pwd_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(f.read(), password=pwd_bytes)

def save_cert(cert, path):
    """Saves a certificate to disk."""
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(path):
    """Loads a certificate from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_csr(path):
    """Loads a CSR from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())

def get_sans_from_ext_content(content):
    """
    Parses the user-editable text content to extract DNS and IP SANs.
    """
    sans = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line.upper().startswith("DNS"):
            parts = line.split('=')
            if len(parts) > 1:
                sans.append(x509.DNSName(parts[1].strip()))
        elif line.upper().startswith("IP"):
            parts = line.split('=')
            if len(parts) > 1:
                try:
                    ip = ipaddress.ip_address(parts[1].strip())
                    sans.append(x509.IPAddress(ip))
                except ValueError:
                    pass 
    return sans

# --- Routes ---

@app.route('/')
def home_redirect():
    return redirect(url_for('index'))

@app.route('/cert/')
def index():
    # 1. Get List of Cert Folders
    cert_dirs = [d for d in os.listdir(CERT_DIR) if os.path.isdir(os.path.join(CERT_DIR, d))]
    
    # 2. Check Root CA
    root_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    root_exists = os.path.exists(root_crt_path)
    
    root_subject = None
    if root_exists:
        try:
            root_cert_obj = load_cert(root_crt_path)
            root_subject = root_cert_obj.subject
        except:
            pass # Handle corrupted root cert gracefully

    # 3. Analyze Certificates for Status Colors
    analyzed_certs = []
    
    for fqdn in cert_dirs:
        crt_path = os.path.join(CERT_DIR, fqdn, f"{fqdn}.crt")
        status = "pending" # Default if no CRT exists
        
        if os.path.exists(crt_path):
            try:
                cert_obj = load_cert(crt_path)
                issuer = cert_obj.issuer
                subject = cert_obj.subject
                
                if issuer == subject:
                    status = "blue" # Self-signed
                elif root_subject and issuer == root_subject:
                    status = "green" # Signed by OUR Root
                else:
                    status = "red" # Signed by unknown
            except Exception:
                status = "error" # Corrupt file
        
        analyzed_certs.append({
            'fqdn': fqdn,
            'status': status
        })

    return render_template('index.html', 
                           certs=analyzed_certs, 
                           root_exists=root_exists, 
                           root_filename=f"{ROOT_CA_NAME}.crt")

@app.route('/cert/download_root')
def download_root():
    return send_from_directory(ROOT_DIR, f"{ROOT_CA_NAME}.crt", as_attachment=True)

@app.route('/cert/create_root', methods=['GET', 'POST'])
def create_root():
    if request.method == 'GET':
        return render_template('create_root.html')

    # Handle POST request: Process the form
    cn = request.form.get('cn', 'My Internal rootCA').strip()
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
        # 2. Generate Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        if password:
            algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))    
        else:
            algorithm = serialization.NoEncryption()

        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=algorithm
        )
        
        with open(key_file, "wb") as f:
            f.write(pem_key)

        # 3. Build the Subject Name dynamically
        name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
        if st: name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
        if city: name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
        if org: name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        if org_unit: name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
        if email: name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = x509.Name(name_attributes)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )

        cert = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256()
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
        
        if not fqdn:
            flash("FQDN is required", "error")
            return redirect(url_for('create_cert'))

        cert_path = os.path.join(CERT_DIR, fqdn)
        if os.path.exists(cert_path):
            flash(f'Certificate for {fqdn} already exists.', 'error')
            return redirect(url_for('create_cert'))
            
        os.makedirs(cert_path)
        
        key_file = os.path.join(cert_path, f"{fqdn}.key")
        csr_file = os.path.join(cert_path, f"{fqdn}.csr")
        ext_file = os.path.join(cert_path, f"{fqdn}.v3.ext")

        try:
            # 1. Create EXT file
            ext_content = f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {fqdn}
"""
            with open(ext_file, 'w') as f:
                f.write(ext_content)

            # 2. Generate Key
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            save_key(private_key, key_file)

            # 3. Generate CSR
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
            
            with open(csr_file, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

            flash(f'CSR and Key created for {fqdn}. Please Sign it now.', 'success')
            return redirect(url_for('manage_cert', fqdn=fqdn))

        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/cert/manage/<fqdn>')
def manage_cert(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    
    # Check if files exist
    if not os.path.exists(cert_path):
        flash(f"Certificate {fqdn} not found.", "error")
        return redirect(url_for('index'))

    ext_file = os.path.join(cert_path, f"{fqdn}.v3.ext")
    csr_file = os.path.join(cert_path, f"{fqdn}.csr")
    
    ext_content = ""
    if os.path.exists(ext_file):
        with open(ext_file, 'r') as f:
            ext_content = f.read()

    has_crt = os.path.exists(os.path.join(cert_path, f"{fqdn}.crt"))
    has_p12 = os.path.exists(os.path.join(cert_path, f"{fqdn}.p12"))

    # Parse CSR to get current details
    csr_details = {
        'cn': fqdn,
        'c': '',
        'o': '',
        'ou': ''
    }
    
    if os.path.exists(csr_file):
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
            pass # Could not parse CSR, default to empty

    return render_template('manage.html', fqdn=fqdn, ext_content=ext_content, has_crt=has_crt, has_p12=has_p12, csr=csr_details)

@app.route('/cert/update_details/<fqdn>', methods=['POST'])
def update_details(fqdn):
    # Retrieve form data
    new_cn = request.form.get('cn', '').strip()
    c = request.form.get('c', '').strip()
    o = request.form.get('o', '').strip()
    ou = request.form.get('ou', '').strip()
    
    if not new_cn:
        flash("Common Name (FQDN) is required.", "error")
        return redirect(url_for('manage_cert', fqdn=fqdn))

    cert_path = os.path.join(CERT_DIR, fqdn)
    key_path = os.path.join(cert_path, f"{fqdn}.key")
    
    # Load existing private key
    if not os.path.exists(key_path):
         flash("Private key not found. Cannot regenerate CSR.", "error")
         return redirect(url_for('manage_cert', fqdn=fqdn))
         
    try:
        private_key = load_key(key_path)
        
        # Build new Subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, c),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, new_cn),
        ])

        # Generate new CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256())
        )
        
        # Logic for handling Name Change vs Same Name
        if new_cn == fqdn:
            # Simple overwrite
            csr_path = os.path.join(cert_path, f"{fqdn}.csr")
            with open(csr_path, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
            flash("Certificate details updated (CSR regenerated).", "success")
            return redirect(url_for('manage_cert', fqdn=fqdn))
        else:
            # Rename required
            new_cert_path = os.path.join(CERT_DIR, new_cn)
            if os.path.exists(new_cert_path):
                flash(f"Destination {new_cn} already exists.", "error")
                return redirect(url_for('manage_cert', fqdn=fqdn))
            
            # 1. Overwrite CSR in current folder first (simplifies move)
            old_csr_path = os.path.join(cert_path, f"{fqdn}.csr")
            with open(old_csr_path, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
                
            # 2. Update v3.ext if it contains the OLD name
            ext_path = os.path.join(cert_path, f"{fqdn}.v3.ext")
            if os.path.exists(ext_path):
                with open(ext_path, 'r') as f:
                    content = f.read()
                # Simple string replace for the mandatory field
                content = content.replace(f"DNS.1 = {fqdn}", f"DNS.1 = {new_cn}")
                with open(ext_path, 'w') as f:
                    f.write(content)
            
            # 3. Rename internal files
            # Iterate through known extensions to rename: key, csr, crt, v3.ext, p12
            for ext in ['.key', '.csr', '.crt', '.v3.ext', '.p12']:
                old_f = os.path.join(cert_path, f"{fqdn}{ext}")
                new_f = os.path.join(cert_path, f"{new_cn}{ext}")
                if os.path.exists(old_f):
                    os.rename(old_f, new_f)
            
            # 4. Rename Directory
            os.rename(cert_path, new_cert_path)
            
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

    cert_path = os.path.join(CERT_DIR, fqdn)
    csr_path = os.path.join(cert_path, f"{fqdn}.csr")
    crt_path = os.path.join(cert_path, f"{fqdn}.crt")
    ext_path = os.path.join(cert_path, f"{fqdn}.v3.ext")
    
    ca_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    ca_key_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")

    try:
        csr = load_csr(csr_path)
        ca_cert = load_cert(ca_crt_path)
        ca_key = load_key(ca_key_path, password=password)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), 
            critical=False
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), 
            critical=False
        )

        if os.path.exists(ext_path):
            with open(ext_path, 'r') as f:
                content = f.read()
            sans = get_sans_from_ext_content(content)
            if sans:
                builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        cert = builder.sign(ca_key, hashes.SHA256())
        save_cert(cert, crt_path)
        
        flash('Signed by Root CA successfully.', 'success')

    except ValueError:
        flash('Incorrect Password for Root CA Key.', 'error')
    except Exception as e:
        flash(f'Signing failed: {str(e)}', 'error')
    
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/sign_self/<fqdn>')
def sign_self(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    csr_path = os.path.join(cert_path, f"{fqdn}.csr")
    key_path = os.path.join(cert_path, f"{fqdn}.key")
    crt_path = os.path.join(cert_path, f"{fqdn}.crt")
    ext_path = os.path.join(cert_path, f"{fqdn}.v3.ext")

    try:
        csr = load_csr(csr_path)
        private_key = load_key(key_path)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(csr.subject) # Self signed
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), 
            critical=False
        )

        if os.path.exists(ext_path):
            with open(ext_path, 'r') as f:
                content = f.read()
            sans = get_sans_from_ext_content(content)
            if sans:
                builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        cert = builder.sign(private_key, hashes.SHA256())
        save_cert(cert, crt_path)
        
        flash('Self-signed successfully.', 'success')
    except Exception as e:
        flash(f'Signing failed: {str(e)}', 'error')
    
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/create_p12/<fqdn>', methods=['POST'])
def create_p12(fqdn):
    password = request.form.get('password', '')
    cert_path = os.path.join(CERT_DIR, fqdn)
    key_path = os.path.join(cert_path, f"{fqdn}.key")
    crt_path = os.path.join(cert_path, f"{fqdn}.crt")
    p12_path = os.path.join(cert_path, f"{fqdn}.p12")

    try:
        private_key = load_key(key_path)
        cert = load_cert(crt_path)

        p12 = pkcs12.serialize_key_and_certificates(
            name=fqdn.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

        with open(p12_path, "wb") as f:
            f.write(p12)

        flash('PF12 container created successfully.', 'success')
    except Exception as e:
        flash(f'PF12 creation failed: {str(e)}', 'error')
        
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/cert/delete/<fqdn>')
def delete_cert(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    try:
        shutil.rmtree(cert_path)
        flash(f'Certificate {fqdn} deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting: {str(e)}', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)