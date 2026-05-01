# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run locally
pip install -r requirements.txt
python app.py                  # http://localhost:5000

# Docker (recommended)
docker compose up -d           # start
docker compose down            # stop
docker build -t cert-manager:latest .
```

No test runner or linter is configured.

## Architecture

This is a web-based PKI management tool built with Flask. Users can create Root CAs, generate RSA keys and CSRs, sign certificates, and export PKCS#12 bundles — all through a web UI.

**`app.py`** is a monolithic ~575-line file containing all routes, helper functions, and cryptographic logic. There are no separate service or model layers.

**Data flow:**
1. Flask route handler receives the HTTP request
2. Handler calls helper functions (`save_key`, `load_cert`, `get_sans_from_ext_content`, etc.) that read/write the filesystem
3. Route renders a Jinja2 template with result data and flash messages

**Filesystem layout (runtime, gitignored):**
```
certs/<fqdn>/
  <fqdn>.key       # 2048-bit RSA private key
  <fqdn>.csr       # certificate signing request
  <fqdn>.crt       # signed certificate
  <fqdn>.v3.ext    # X.509 v3 extensions file
  <fqdn>.p12       # PKCS#12 export

rootCA/
  rootca.key       # 4096-bit RSA private key
  rootca.crt       # self-signed Root CA certificate
```

**Key routes in `app.py`:**
- `GET/POST /cert/create_root` — generates Root CA key + self-signed cert
- `GET/POST /cert/create` — generates RSA key + CSR for an FQDN
- `GET /cert/manage/<fqdn>` — certificate management page (sign, export, edit)
- `POST /cert/sign_root/<fqdn>` — signs CSR with Root CA
- `POST /cert/sign_self/<fqdn>` — self-signs CSR
- `POST /cert/create_p12/<fqdn>` — exports to PKCS#12

## Configuration

Environment variables (via `.env`, see `.env-sample`):

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `dev-secret-key` | Flask session secret |
| `CERT_DIR` | `./certs` | Certificate storage directory |
| `ROOT_DIR` | `./rootCA` | Root CA storage directory |
| `ROOT_CA_NAME` | `my-root-ca` | Root CA filename (without extension) |

## Notes

- `cert-manager.sh` is a legacy CLI tool using OpenSSL shell commands. It is not used by the Flask app and exists only as a reference.
- All PKI operations use the Python `cryptography` library directly — no subprocess calls to OpenSSL.
- The app runs with `debug=True` even in Docker; `FLASK_ENV=production` in docker-compose does not change this.
