# Certificate Revocation List (CRL)

Crypto/build helpers are orchestrated by ``pki.services.revocation``.
The signed CRL PEM is stored in SQLite table ``crl``.

## Service API

```python
from pki.services import revoke_by_cn, list_revoked
from pki.ca.root_ca import certificate_to_pem

revoke_by_cn("Alice")
for entry in list_revoked():
    print(entry.serial_number, entry.revocation_date)
```

## Relation to course concepts

| Course idea | Here |
| ----------- | ---- |
| Révocation / CRL | `revoke_serial` / `revoke_by_cn` |
| SP (publication) | CRL row in SQLite (exportable as PEM) |
| AC / CA | CRL signed by Root CA |

## Next step

Web UI can expose “Revoke” and “Download CRL” using these services.
See [Validation](validation.md).
