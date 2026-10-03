"""RSA key generation and encrypted PEM file I/O for MiniPKI.

In a PKI, the private key is the trust root of everything that follows.
If someone steals the Root CA private key, they can mint fake certificates.

We protect private keys with:

1. **Encrypted PEM** — PKCS#8 encrypted with a passphrase using
   ``BestAvailableEncryption`` (OpenSSL picks a strong KDF + cipher).
   The passphrase lives in ``.env`` as ``MINIPKI_PRIVATE_KEY_PASSPHRASE``.
2. **SQLite at rest** — the Root CA encrypted PEM is stored in the database
   (``storage/minipki.db``), not as loose key files in the repo.

A hardware security module (HSM) would be stronger still, but is out of scope
for a student MVP; passphrase-encrypted PEM is the secure approach we use.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from pki.config import get_settings


def generate_rsa_private_key(key_size: int | None = None) -> RSAPrivateKey:
    """Create a new RSA private key.

    Parameters
    ----------
    key_size:
        Modulus length in bits. Defaults to the CA size from config
        (``MINIPKI_CA_KEY_SIZE``, usually 4096). Use the client size from
        config when issuing end-entity certificates.
    """
    settings = get_settings()
    if key_size is None:
        key_size = settings.ca_key_size

    if key_size < settings.min_key_size:
        raise ValueError(
            f"RSA key size must be at least {settings.min_key_size} bits for this MVP"
        )

    return rsa.generate_private_key(
        public_exponent=settings.rsa_public_exponent,
        key_size=key_size,
    )


def get_public_key(private_key: RSAPrivateKey) -> RSAPublicKey:
    """Derive the matching public key from a private key."""
    return private_key.public_key()


def _resolve_passphrase(passphrase: bytes | str | None) -> bytes:
    """Use an explicit passphrase, or fall back to config / ``.env``."""
    if passphrase is None:
        return get_settings().passphrase_bytes()
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if not passphrase:
        raise ValueError("Passphrase must not be empty when encrypting private keys")
    return passphrase


def private_key_to_pem(
    private_key: RSAPrivateKey,
    passphrase: bytes | str | None = None,
) -> bytes:
    """Serialize a private key to an **encrypted** PEM (PKCS#8).

    ``BestAvailableEncryption`` asks OpenSSL for the strongest KDF/cipher it
    supports for password-based PKCS#8. The file on disk is useless without
    the passphrase from ``.env``.
    """
    password = _resolve_passphrase(passphrase)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def public_key_to_pem(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM (SubjectPublicKeyInfo).

    Public keys are meant to be shared, so they are not encrypted.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(
    pem_data: bytes,
    passphrase: bytes | str | None = None,
) -> RSAPrivateKey:
    """Load an RSA private key from encrypted PEM bytes (e.g. from SQLite)."""
    password = _resolve_passphrase(passphrase)
    key = serialization.load_pem_private_key(pem_data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError(f"Expected an RSA private key, got {type(key).__name__}")
    return key


def load_private_key(
    path: str | Path,
    passphrase: bytes | str | None = None,
) -> RSAPrivateKey:
    """Load an RSA private key from an encrypted PEM file on disk."""
    return load_private_key_pem(Path(path).read_bytes(), passphrase=passphrase)


def load_public_key(path: str | Path) -> RSAPublicKey:
    """Load an RSA public key from a PEM file on disk."""
    pem_data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError(f"Expected an RSA public key, got {type(key).__name__}")
    return key


def save_private_key(
    private_key: RSAPrivateKey,
    path: str | Path,
    passphrase: bytes | str | None = None,
) -> Path:
    """Write an encrypted private-key PEM and restrict file permissions.

    On Unix we set mode ``0o600`` (owner read/write only) so other local users
    cannot read the ciphertext either. On platforms without ``chmod``, we
    still write the encrypted file.
    """
    settings = get_settings()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = private_key_to_pem(private_key, passphrase=passphrase)
    path.write_bytes(pem)

    # Best-effort hardening: ignore if the OS does not support chmod.
    try:
        os.chmod(path, settings.private_key_file_mode)
    except OSError:
        pass

    return path


def save_public_key(public_key: RSAPublicKey, path: str | Path) -> Path:
    """Write a public key to a PEM file (no encryption / special mode)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_key_to_pem(public_key))
    return path
