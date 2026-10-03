# Certificate issuance (CSR-based)

Helpers: `src/pki/certificates/certificate.py`  
Service: `pki.services.certificates`

## Why CSR

The CA must **not** hold (or generate) the client private key. The client creates
a key + CSR locally (e.g. with OpenSSL), then uploads **only the CSR**.

```text
Client (OpenSSL) → CSR upload → admin issues → certificate in SQLite
                   (private key never leaves the client)
```

## OpenSSL (client side)

```bash
openssl genrsa -out alice.key 2048
openssl req -new -key alice.key -out alice.csr \
  -subj "/C=MA/O=MiniPKI Clients/CN=Alice"
```

Upload `alice.csr` via the UI (`/csrs`) or `POST /api/csrs` with the PEM body.
Keep `alice.key` secret.

## Service API

```python
from pki.services import submit_csr_pem, issue_certificate

# Web / production flow
csr_id = submit_csr_pem(open("alice.csr", "rb").read())
issued = issue_certificate(csr_id=csr_id)  # admin-only in the web layer

# Unit-test helper only (generates a key in memory; still does not store it):
# create_csr_for_common_name("Alice")
```

## Access control (web)

| Action | Who |
| ------ | --- |
| Upload CSR, validate, view CRL / Root CA | Anyone |
| Issue certificate | Admin (`MINIPKI_ADMIN_PASSWORD`) |
| Revoke certificate | Admin |

## Issued certificate fields

| Field / extension | Value |
| ----------------- | ----- |
| Subject | From CSR |
| Issuer | Root CA |
| Validity | `MINIPKI_CLIENT_VALIDITY_DAYS` (default 365) |
| Serial | Large random |
| BasicConstraints | `CA:FALSE` |
| KeyUsage | `digitalSignature`, `keyEncipherment` |
| ExtendedKeyUsage | `clientAuth` |

## Next

See [CRL / revocation](crl.md).
