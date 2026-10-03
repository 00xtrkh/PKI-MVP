"""Central configuration for MiniPKI.

Tunable values and the SQLite database path live here. Secrets such as the
private-key passphrase come from a ``.env`` file (never committed).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

PASSPHRASE_ENV = "MINIPKI_PRIVATE_KEY_PASSPHRASE"
ADMIN_PASSWORD_ENV = "MINIPKI_ADMIN_PASSWORD"


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings for the MVP."""

    ca_key_size: int = 4096
    client_key_size: int = 2048
    min_key_size: int = 2048
    rsa_public_exponent: int = 65537

    ca_common_name: str = "MiniPKI Root CA"
    ca_organization: str = "MiniPKI"
    ca_country: str = "MA"
    ca_validity_days: int = 3650
    client_validity_days: int = 365
    client_organization: str = "MiniPKI Clients"
    crl_next_update_days: int = 7

    # SQLite is the system of record (web-ready).
    storage_dir: Path = PROJECT_ROOT / "storage"
    database_name: str = "minipki.db"

    private_key_file_mode: int = 0o600
    private_key_passphrase: str = ""
    # Protects issue + revoke in the web UI / API (empty = disabled / deny).
    admin_password: str = ""

    def passphrase_bytes(self) -> bytes:
        if not self.private_key_passphrase:
            raise ValueError(
                f"Missing private-key passphrase. Set {PASSPHRASE_ENV} in your "
                f".env file (see .env.example). "
                "We encrypt PEM files at rest; an empty passphrase is not allowed."
            )
        return self.private_key_passphrase.encode("utf-8")

    @property
    def database_path(self) -> Path:
        return self.storage_dir / self.database_name


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings from environment / ``.env`` (cached)."""
    storage = os.getenv("MINIPKI_STORAGE_DIR", "").strip()
    storage_dir = Path(storage) if storage else PROJECT_ROOT / "storage"
    db_name = os.getenv("MINIPKI_DATABASE_NAME", "minipki.db").strip() or "minipki.db"

    return Settings(
        ca_key_size=_env_int("MINIPKI_CA_KEY_SIZE", 4096),
        client_key_size=_env_int("MINIPKI_CLIENT_KEY_SIZE", 2048),
        min_key_size=_env_int("MINIPKI_MIN_KEY_SIZE", 2048),
        ca_common_name=os.getenv("MINIPKI_CA_CN", "MiniPKI Root CA").strip()
        or "MiniPKI Root CA",
        ca_organization=os.getenv("MINIPKI_CA_ORG", "MiniPKI").strip() or "MiniPKI",
        ca_country=os.getenv("MINIPKI_CA_COUNTRY", "MA").strip() or "MA",
        ca_validity_days=_env_int("MINIPKI_CA_VALIDITY_DAYS", 3650),
        client_validity_days=_env_int("MINIPKI_CLIENT_VALIDITY_DAYS", 365),
        client_organization=os.getenv("MINIPKI_CLIENT_ORG", "MiniPKI Clients").strip()
        or "MiniPKI Clients",
        crl_next_update_days=_env_int("MINIPKI_CRL_NEXT_UPDATE_DAYS", 7),
        storage_dir=storage_dir,
        database_name=db_name,
        private_key_passphrase=os.getenv(PASSPHRASE_ENV, "").strip(),
        admin_password=os.getenv(ADMIN_PASSWORD_ENV, "").strip(),
    )


def ca_key_size() -> int:
    return get_settings().ca_key_size


def client_key_size() -> int:
    return get_settings().client_key_size
