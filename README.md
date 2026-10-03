# MiniPKI

Lightweight X.509 Public Key Infrastructure MVP for the ENSET TP
(*Conception d'une Infrastructure a Cles Publiques*).

## Goals

- Root CA with self-signed certificate (created on first app run)
- CSR-based issuance: clients create keys with OpenSSL and upload CSR only
- Admin-only issue and revoke (`MINIPKI_ADMIN_PASSWORD`)
- Certificate validation (signature, expiry, CRL)
- Flask UI (Jinja) + JSON API
- SQLite persistence via SQLAlchemy ORM

## Stack

- Python 3.11+
- Flask + Jinja2 + Flask-SQLAlchemy
- [`cryptography`](https://cryptography.io/)
- OpenSSL (optional external verification)

## Architecture

```text
pki.web.ui / pki.web.api   <- HTTP (templates + JSON)
       |
       +-- pki.services.*  <- application logic
              |
              +-- pki.ca / certificates / validation   (crypto)
              +-- pki.db.models                        (ORM)
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
cp .env.example .env
# set MINIPKI_PRIVATE_KEY_PASSPHRASE and MINIPKI_ADMIN_PASSWORD
```

Database file (default): `storage/minipki.db` (gitignored).

## Run with Docker

```bash
cp .env.example .env
# set MINIPKI_PRIVATE_KEY_PASSPHRASE and MINIPKI_ADMIN_PASSWORD in .env

docker compose up --build -d
# open http://127.0.0.1:5000
```

```bash
docker compose logs -f
docker compose down
```

## Run locally

```bash
source .venv/bin/activate
python -m pki.web
# open http://127.0.0.1:5000
```

On startup the app creates the SQLite schema and generates a Root CA (and empty CRL)
if they do not already exist.

### Client CSR (OpenSSL)

```bash
openssl genrsa -out alice.key 2048
openssl req -new -key alice.key -out alice.csr \
  -subj "/C=MA/O=MiniPKI Clients/CN=Alice"
```

Upload `alice.csr` on `/csrs`. An admin logs in to issue. Never upload `alice.key`.

### UI pages

| Path | Feature |
| ---- | ------- |
| `/` | Dashboard |
| `/login` | Admin login (issue / revoke) |
| `/root-ca` | Root CA details + PEM |
| `/csrs` | OpenSSL instructions + upload CSR; admin issues |
| `/certificates` | List; admin revokes |
| `/validate` | Validate by serial or PEM |
| `/crl` | Revocation list |

### JSON API (`/api/...`)

| Method | Path | Auth | Notes |
| ------ | ---- | ---- | ----- |
| GET | `/api/health` | public | Liveness |
| GET | `/api/root-ca` | public | Root CA metadata + PEM |
| GET | `/api/csrs` | public | List CSRs |
| POST | `/api/csrs` | public | Upload CSR PEM |
| POST | `/api/certificates/issue` | Basic `admin` | Issue from CSR |
| GET | `/api/certificates` | public | List issued |
| POST | `/api/revoke` | Basic `admin` | Revoke by CN or serial |
| GET | `/api/crl` | public | Revoked entries |
| POST | `/api/validate` | public | Validate serial or PEM |

## Project layout

```text
src/pki/
  config.py
  db/             # ORM models
  ca/             # Key management + Root CA
  certificates/   # CSR helpers
  revocation/     # CRL helpers
  validation/     # Certificate validator
  services/       # Application services
  web/            # Flask UI + JSON API
storage/          # SQLite DB at runtime
docs/
```

## Docs

- [Key management](docs/keys.md)
- [Configuration](docs/config.md)
- [Root CA](docs/root_ca.md)
- [Certificate issuance](docs/certificate.md)
- [CRL / revocation](docs/crl.md)
- [Validation](docs/validation.md)
- [SQLite storage](docs/storage.md)

## License

Academic / course project use.
