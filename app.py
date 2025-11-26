import os
import subprocess
import shutil
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for flash messages

CERT_DIR = "./certs"
ROOT_DIR = "./rootCA"
ROOT_CA_NAME = ""

# Ensure dirs exist
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(ROOT_DIR, exist_ok=True)

def run_command(cmd):
    """Executes shell commands and returns success status"""
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True, result.stdout.decode()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode()

@app.route('/')
def index():
    # List all certificates (directories in certs folder)
    certs = [d for d in os.listdir(CERT_DIR) if os.path.isdir(os.path.join(CERT_DIR, d))]
    
    # Check if Root CA exists
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

    # Generate Key
    run_command(f"openssl genrsa -out {key_file} 4096")
    
    # Generate Cert
    subj = f"/C={c}/CN={cn}"
    success, msg = run_command(f"openssl req -x509 -new -nodes -key {key_file} -sha256 -days 3650 -out {crt_file} -subj \"{subj}\"")
    
    if success:
        flash('Root CA created successfully.', 'success')
    else:
        flash(f'Error creating Root CA: {msg}', 'error')
        
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
        run_command(f"openssl genrsa -out {key_file} 2048")

        # 3. Generate CSR
        subj = f"/C={c}/O={o}/OU={ou}/CN={fqdn}"
        success, msg = run_command(f"openssl req -new -key {key_file} -out {csr_file} -subj \"{subj}\"")

        if success:
            flash(f'CSR and Key created for {fqdn}. Please Sign it now.', 'success')
            return redirect(url_for('manage_cert', fqdn=fqdn))
        else:
            flash(f'Error: {msg}', 'error')
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

    # Check status
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
    csr = os.path.join(cert_path, f"{fqdn}.csr")
    crt = os.path.join(cert_path, f"{fqdn}.crt")
    ext = os.path.join(cert_path, f"{fqdn}.v3.ext")
    
    ca_crt = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.crt")
    ca_key = os.path.join(ROOT_DIR, f"{ROOT_CA_NAME}.key")

    cmd = f"openssl x509 -req -in {csr} -CA {ca_crt} -CAkey {ca_key} -CAcreateserial -out {crt} -days 365 -sha256 -extfile {ext}"
    success, msg = run_command(cmd)
    
    if success:
        flash('Signed by Root CA successfully.', 'success')
    else:
        flash(f'Signing failed: {msg}', 'error')
    
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/sign_self/<fqdn>')
def sign_self(fqdn):
    cert_path = os.path.join(CERT_DIR, fqdn)
    csr = os.path.join(cert_path, f"{fqdn}.csr")
    key = os.path.join(cert_path, f"{fqdn}.key")
    crt = os.path.join(cert_path, f"{fqdn}.crt")
    ext = os.path.join(cert_path, f"{fqdn}.v3.ext")

    cmd = f"openssl x509 -req -in {csr} -signkey {key} -out {crt} -days 365 -sha256 -extfile {ext}"
    success, msg = run_command(cmd)
    
    if success:
        flash('Self-signed successfully.', 'success')
    else:
        flash(f'Signing failed: {msg}', 'error')
    
    return redirect(url_for('manage_cert', fqdn=fqdn))

@app.route('/create_p12/<fqdn>', methods=['POST'])
def create_p12(fqdn):
    password = request.form.get('password', '')
    cert_path = os.path.join(CERT_DIR, fqdn)
    key = os.path.join(cert_path, f"{fqdn}.key")
    crt = os.path.join(cert_path, f"{fqdn}.crt")
    p12 = os.path.join(cert_path, f"{fqdn}.p12")

    # Only doing p12 as PEM is just concat
    cmd = f"openssl pkcs12 -export -inkey {key} -in {crt} -out {p12} -passout pass:{password}"
    success, msg = run_command(cmd)

    if success:
        flash('PF12 container created successfully.', 'success')
    else:
        flash(f'PF12 creation failed: {msg}', 'error')
        
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