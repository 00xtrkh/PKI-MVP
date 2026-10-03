# SQLite storage (ORM)

All durable PKI state lives in SQLite (`storage/minipki.db` by default),
accessed through **Flask-SQLAlchemy** models in `pki.db.models`.

## Layers

| Layer | Responsibility |
| ----- | -------------- |
| `pki.db.models` / `extensions` | ORM models + shared `db` session |
| `pki.ca` / `certificates` / `validation` | Crypto only — no SQL |
| `pki.services` | Orchestrates crypto + ORM |
| `pki.web` | Flask UI (Jinja) + JSON API |

## Tables

| Table | Model | Contents |
| ----- | ----- | -------- |
| `root_ca` | `RootCa` | Encrypted Root CA private key PEM + certificate PEM |
| `csrs` | `Csr` | Submitted CSRs (`pending` / `issued`) — **no client private keys** |
| `certificates` | `Certificate` | Issued cert PEM + serial, CN, validity, `revoked_at` |
| `crl` | `Crl` | Current signed CRL PEM |

## Config

```bash
MINIPKI_STORAGE_DIR=storage
MINIPKI_DATABASE_NAME=minipki.db
MINIPKI_PRIVATE_KEY_PASSPHRASE=...
```

## Bootstrap

`create_app()` runs `db.create_all()`, then `ensure_root_ca()` and
`ensure_empty_crl()` so the first process start generates the trust anchor
when none exists.

## Security note

Client private keys are **not** stored in the database. `create_csr_for_common_name`
returns the key to the caller in memory; only the CSR PEM is persisted.
