"""Cryptographic utilities for MingSeal Immutable Memory."""

from .signing import LocalSigner, SigningKey, compute_commitment
from .ecdh import (
    ECDHKeyManager,
    derive_shared_secret,
    encrypt_with_shared_secret,
    decrypt_with_shared_secret,
    SecureMessage,
)

__all__ = [
    "LocalSigner",
    "SigningKey",
    "compute_commitment",
    "ECDHKeyManager",
    "derive_shared_secret",
    "encrypt_with_shared_secret",
    "decrypt_with_shared_secret",
    "SecureMessage",
]
