import os
import shutil
import datetime
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, flash
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

def load_key(path):
    """Loads a private key from disk."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

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
    Look for lines under [alt_names] like DNS.1 = example.com
    """
    sans = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        # Simple parsing logic to mimic OpenSSL config reading
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
                    pass # Invalid IP, skip
    return sans

# --- Routes ---

@app.route('/')
def index():
    certs = [d for d in os.listdir(CERT_DIR) if os.path.isdir(os.path.join(CERT_DIR, d))]
    root_exists = os.path.exists(os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt"))
    return render_template('index.html', certs=certs, root_exists=root_exists)

@app.route('/create_root', methods=['POST'])
def create_root():
    cn = request.form.get('cn', 'My Internal rootCA')
    c = request.form.get('c', 'NL')
    
    key_file = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")
    crt_file = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")

    if os.path.exists(crt_file):
        flash('Root CA already exists!', 'error')
        return redirect(url_for('index'))

    try:
        # 1. Generate Private Key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        save_key(private_key, key_file)

        # 2. Build Subject/Issuer (Self-signed)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, c),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        # 3. Build Certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject) # Self-signed
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            # Root CA Extensions
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True, # Critical for CA
                crl_sign=True,      # Critical for CA
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
            .sign(private_key, hashes.SHA256())
        )

        save_cert(cert, crt_file)
        flash('Root CA created successfully.', 'success')

    except Exception as e:
        flash(f'Error creating Root CA: {str(e)}', 'error')
        
    return redirect(url_for('index'))

@app.route('/create', methods=['GET', 'POST'])
def create_cert():
    if request.method == 'POST':
        fqdn = request.form['fqdn']
        c = request.form.get('c', 'NL')
        o = request.form.get('o', 'Hiddenmaces.nl')
        ou = request.form.get('ou', 'IT')
        
        cert_path = os.path.join(CERT_DIR, fqdn)
        if os.path.exists(cert_path):
            flash(f'Certificate for {fqdn} already exists.', 'error')
            return redirect(url_for('create_cert'))
            
        os.makedirs(cert_path)
        
        key_file = os.path.join(cert_path, f"{fqdn}.key")
        csr_file = os.path.join(cert_path, f"{fqdn}.csr")
        ext_file = os.path.join(cert_path, f"{fqdn}.v3.ext")

        try:
            # 1. Create EXT file (kept for UI consistency and SAN parsing later)
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
            
            # Save CSR
            with open(csr_file, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

            flash(f'CSR and Key created for {fqdn}. Please Sign it now.', 'success')
            return redirect(url_for('manage_cert', fqdn=fqdn))

        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/manage/<fqdn>')
def manage_cert(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    ext_file = os.path.join(cert_path, f"{fqdn}.v3.ext")
    
    ext_content = ""
    if os.path.exists(ext_file):
        with open(ext_file, 'r') as f:
            ext_content = f.read()

    has_crt = os.path.exists(os.path.join(cert_path, f"{fqdn}.crt"))
    has_p12 = os.path.exists(os.path.join(cert_path, f"{fqdn}.p12"))

    return render_template('manage.html', fqdn=fqdn, ext_content=ext_content, has_crt=has_crt, has_p12=has_p12)

@app.route('/update_ext/<fqdn>', methods=['POST'])
def update_ext(fqdn):
    content = request.form['ext_content']
    ext_file = os.path.join(CERT_DIR, fqdn, f"{fqdn}.v3.ext")
    with open(ext_file, 'w') as f:
        f.write(content)
    flash('Extension file updated.', 'success')
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/sign_root/<fqdn>')
def sign_root(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    csr_path = os.path.join(cert_path, f"{fqdn}.csr")
    crt_path = os.path.join(cert_path, f"{fqdn}.crt")
    ext_path = os.path.join(cert_path, f"{fqdn}.v3.ext")
    
    ca_crt_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    ca_key_path = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")

    try:
        csr = load_csr(csr_path)
        ca_cert = load_cert(ca_crt_path)
        ca_key = load_key(ca_key_path)

        # Build Certificate from CSR
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

        # Add Extensions
        # 1. Basic Constraints & Key Usage (Standard for Server Certs)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        
        # 2. Authority Key Identifier (Links to CA)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), 
            critical=False
        )

        # 3. Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), 
            critical=False
        )

        # 4. Parse user provided text file for SANs
        if os.path.exists(ext_path):
            with open(ext_path, 'r') as f:
                content = f.read()
            sans = get_sans_from_ext_content(content)
            if sans:
                builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        # Sign
        cert = builder.sign(ca_key, hashes.SHA256())
        save_cert(cert, crt_path)
        
        flash('Signed by Root CA successfully.', 'success')
    except Exception as e:
        flash(f'Signing failed: {str(e)}', 'error')
    
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/sign_self/<fqdn>')
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
        builder = builder.issuer_name(csr.subject) # Self signed: Issuer == Subject
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

        # Standard Extensions
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

        # Parse user provided text file for SANs
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

@app.route('/create_p12/<fqdn>', methods=['POST'])
def create_p12(fqdn):
    password = request.form.get('password', '')
    cert_path = os.path.join(CERT_DIR, fqdn)
    key_path = os.path.join(cert_path, f"{fqdn}.key")
    crt_path = os.path.join(cert_path, f"{fqdn}.crt")
    p12_path = os.path.join(cert_path, f"{fqdn}.p12")

    try:
        private_key = load_key(key_path)
        cert = load_cert(crt_path)

        # Serialize to P12
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

@app.route('/delete/<fqdn>')
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