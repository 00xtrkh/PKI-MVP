# Configuration

| File | Committed? | Purpose |
| ---- | ---------- | ------- |
| `src/pki/config.py` | yes | Settings defaults |
| `.env.example` | yes | Template |
| `.env` | **no** | Passphrase + overrides |
| `storage/minipki.db` | **no** | SQLite database |

## Required

```bash
MINIPKI_PRIVATE_KEY_PASSPHRASE=your-long-random-secret
```

## Optional

```bash
MINIPKI_CA_KEY_SIZE=4096
MINIPKI_CLIENT_KEY_SIZE=2048
MINIPKI_MIN_KEY_SIZE=2048
MINIPKI_CA_CN=MiniPKI Root CA
MINIPKI_CA_ORG=MiniPKI
MINIPKI_CA_COUNTRY=MA
MINIPKI_CA_VALIDITY_DAYS=3650
MINIPKI_CLIENT_VALIDITY_DAYS=365
MINIPKI_CLIENT_ORG=MiniPKI Clients
MINIPKI_CRL_NEXT_UPDATE_DAYS=7
MINIPKI_STORAGE_DIR=storage
MINIPKI_DATABASE_NAME=minipki.db
```

See also [SQLite storage](storage.md).
