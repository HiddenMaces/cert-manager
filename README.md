# Cert-manager
A lightweight, web-based interface for managing a private Public Key Infrastructure (PKI). This application allows you to create a Root CA, generate Certificate Signing Requests (CSRs), and sign certificates for your internal development or testing environments without needing to memorize complex OpenSSL commands.

## Features

  * **Root CA Management:** Generate a self-signed Root Certificate Authority.
  * **Certificate Generation:** Create Private Keys and CSRs for specific FQDNs (Fully Qualified Domain Names).
  * **Flexible Signing:**
      * **Sign with Root CA:** Issue certificates trusted by your private Root CA.
      * **Self-Sign:** Create self-signed certificates for standalone use.
  * **Extension Management:** Support for Subject Alternative Names (SANs) via editable extension files.
  * **Export:** Convert signed certificates and keys into PKCS\#12 (`.p12`) format for easy import into Windows/macOS keychains or browsers.
  * **Pure Python:** Uses the `cryptography` library, eliminating dependencies on system-level shell commands.

## Layout
```
cert-manager/
├── certs/              # (Empty, will be mapped to Docker)
├── rootCA/             # (Empty, will be mapped to Docker)
├── templates/
│   ├── layout.html     # template for html pages
│   ├── index.html      # initial page
│   ├── create.html     # creating certs page
│   └── manage.html     # manage certs page
├── app.py              # application
├── Dockerfile          
├── docker-compose.yml
└── requirements.txt    # requirements for app.py
```

## Requirements

  * **Docker** :)

## Configuration

The application uses environment variables for configuration. You can create a `.env` file in the root directory to override defaults.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | `supersecretkey` | Flask session key. Change this for production. |
| `CERT_DIR` | `./certs` | Directory where generated certificates are stored. |
| `ROOT_DIR` | `./rootCA` | Directory where the Root CA key/cert is stored. |
| `ROOT_CA_NAME` | `rootca` | Filename prefix for the Root CA files. |

### Python Dependencies

The application requires the following libraries, these will be installed during build:

  * `Flask` (Web framework)
  * `python-dotenv` (Configuration management)
  * `cryptography` (Crypto operations)

## Docker Support

To run this application in Docker, use the following steps.

**Clone the repository** (or download the files):
```bash
git clone https://github.com/HiddenMaces/cert-manager.git
cd cert-manager
```

**create .env**
```bash
cp .env-sample .env
```

**Run Command:**
```bash
docker build -t cert-manager:latest .
docker compose up -d
```

**Access the Interface:**
Open your web browser and navigate to: `http://localhost:5000`

### Workflow

1.  **Create Root CA:**
      * On the home page, if no Root CA exists, use the form to create one. Provide a Common Name (CN) and Country Code.
      * Download .crt file
        
      When you created the root certificate, don't forget to download the .crt file and import it to your systems as a 'Trusted Root Authority' on the computer account.
      This will make sure any user and application (even running under SYSTEM etc.) will trust your certificates.
2.  **Create a Certificate:**
      * Go to **"Create New Cert"**.
      * Enter the FQDN (e.g., `myserver.local`) and organization details.
      * This generates a Key and a CSR.
3.  **Manage & Sign:**
      * Click **"Manage"** next to the newly created certificate.
      * **Edit Extensions:** If you need specific Subject Alternative Names (DNS or IP), edit the text box, add DNS and/or IP if applicable.
      * Example extension file:
        ``` text
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        extendedKeyUsage = serverAuth
        subjectAltName = @alt_names (mandatory)
        [alt_names]
        DNS.1 = fqdn (mandatory for modern browser)
        DNS.2 = fqdn2 (optional)
        IP.1 = 192.168.1.10 (optional)
        IP.2 = x.x.x.x (optional)
        ```
      * **Sign:** Choose **"Sign with Root CA"** (recommended) or **"Self-Sign"**.
4.  **Export:**
      * Once signed, you can generate a `.p12` file by entering a password and clicking **"Create P12"**.

## License
[MIT](https://choosealicense.com/licenses/mit/)
