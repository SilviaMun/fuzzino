"""
Database encryption for sensitive fields.
Uses Fernet (AES-128-CBC + HMAC-SHA256) from cryptography library.
Key is derived from a passphrase in .env via PBKDF2.
"""

import os
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


_fernet: Fernet | None = None
_SALT_PATH = Path(__file__).parent / "certs" / ".db_salt"


def _get_salt() -> bytes:
    """Get or create a persistent salt for key derivation."""
    os.makedirs(_SALT_PATH.parent, exist_ok=True)
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    salt = os.urandom(16)
    _SALT_PATH.write_bytes(salt)
    os.chmod(str(_SALT_PATH), 0o600)
    return salt


def _derive_key(passphrase: str) -> bytes:
    """Derive a Fernet key from a passphrase using PBKDF2."""
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key


def init_encryption(passphrase: str):
    """Initialize the encryption engine with a passphrase."""
    global _fernet
    key = _derive_key(passphrase)
    _fernet = Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64-encoded ciphertext."""
    if not _fernet:
        return plaintext  # graceful fallback if encryption not initialized
    if not plaintext:
        return plaintext
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decrypt a string. Returns plaintext."""
    if not _fernet:
        return ciphertext
    if not ciphertext:
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        # If decryption fails, it might be unencrypted legacy data
        return ciphertext


def is_encrypted(data: str) -> bool:
    """Check if data looks like Fernet-encrypted (starts with gAAAAA)."""
    return bool(data) and data.startswith("gAAAAA")
