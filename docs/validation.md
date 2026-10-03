# Certificate validation

Pure checks: ``pki.validation.validator``.  
SQLite-backed entry point: ``pki.services.validation``.

```python
from pki.services import validate_certificate_pem, validate_serial
from pki.ca.root_ca import certificate_to_pem

result = validate_certificate_pem(certificate_to_pem(cert))
print(result.status)  # VALID / REVOKED / EXPIRED / …
```

## Reason codes

| Status | Meaning |
| ------ | ------- |
| `VALID` | All checks passed |
| `BAD_FORMAT` | Not a PEM certificate / missing |
| `BAD_SIGNATURE` | Signature does not verify with Root CA |
| `UNKNOWN_ISSUER` | Issuer DN ≠ trusted Root CA |
| `NOT_YET_VALID` / `EXPIRED` | Outside validity window |
| `REVOKED` | Serial listed on CRL |

## Relation to course concepts

| Course idea | Here |
| ----------- | ---- |
| SV (validation) | `validate_certificate` / `validate_certificate_pem` |
