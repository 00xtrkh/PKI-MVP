# Root CA (self-signed trust anchor)

Crypto: `src/pki/ca/root_ca.py`  
Service: `pki.services.ca.initialize_root_ca` / `load_root_ca`

## What a Root CA is

```text
Issuer  = MiniPKI Root CA
Subject = MiniPKI Root CA   # self-signed
```

## Persistence

SQLite table `root_ca`: encrypted private-key PEM + certificate PEM.  
See [storage.md](storage.md).

## Certificate fields (MVP)

| Field / extension | Value |
| ----------------- | ----- |
| Subject / Issuer | `C`, `O`, `CN` from config |
| Validity | `MINIPKI_CA_VALIDITY_DAYS` (default 3650) |
| Signature | RSA + SHA-256 |
| BasicConstraints | `CA:TRUE` (critical) |
| KeyUsage | `keyCertSign`, `cRLSign`, `digitalSignature` |

## Service API

```python
from pki.services import initialize_root_ca, load_root_ca

initialize_root_ca(force=True)
root = load_root_ca()
```

## Next

See [Certificate issuance](certificate.md).
