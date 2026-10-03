# Key management in MiniPKI

Module: `src/pki/ca/key_manager.py`  
Config: `src/pki/config.py` + `.env`

## Why keys matter

| Key | Who uses it | If compromised |
| --- | ----------- | -------------- |
| Root CA private key | Signs client certificates and CRLs | Attacker can forge certificates |
| Client private key | Proves possession of the cert | Attacker can impersonate that client |

## Protection model

| Layer | What we do |
| ----- | ---------- |
| Encryption at rest | `BestAvailableEncryption(passphrase)` → `BEGIN ENCRYPTED PRIVATE KEY` |
| Passphrase | `.env` → `MINIPKI_PRIVATE_KEY_PASSPHRASE` (gitignored) |
| Storage | Encrypted Root CA PEM in SQLite (`storage/minipki.db`) |
| Client keys | **Not** stored by the CA (CSR flow; key stays with the client) |

## Example

```python
from pki.ca.key_manager import generate_rsa_private_key, private_key_to_pem
from pki.config import get_settings

settings = get_settings()
private_key = generate_rsa_private_key(settings.ca_key_size)
pem = private_key_to_pem(private_key)  # encrypted with passphrase from .env
```

Prefer `pki.services.ca.initialize_root_ca()` so the key is saved in SQLite.

## Next

See [Root CA](root_ca.md) and [SQLite storage](storage.md).
