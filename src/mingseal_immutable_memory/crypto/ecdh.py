"""
ECDH Key Exchange for Secure Communication.

Provides Elliptic Curve Diffie-Hellman key exchange capabilities
for secure communication between agents. This is preparation for
Layer 3 (encrypted memory sharing).
"""

import hashlib
import os
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class ECDHKeyManager:
    """
    Manages ECDH key exchange for agent communication.
    
    Uses SECP256K1 curve (same as Bitcoin) for compatibility.
    Provides:
    - Key pair generation
    - Shared secret derivation
    - Key agreement
    - Symmetric key derivation
    """
    
    CURVE = ec.SECP256K1()
    
    def __init__(self):
        """Initialize with a new key pair."""
        self._private_key = ec.generate_private_key(
            self.CURVE,
            default_backend()
        )
        self._public_key = self._private_key.public_key()
    
    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> "ECDHKeyManager":
        """
        Create a key manager from an existing private key.
        
        Args:
            private_key_hex: Hex-encoded private key
        
        Returns:
            ECDHKeyManager instance
        """
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key,
        )
        
        manager = cls.__new__(cls)
        private_pem = bytes.fromhex(private_key_hex)
        manager._private_key = load_der_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        manager._public_key = manager._private_key.public_key()
        
        return manager
    
    def get_public_key_bytes(self) -> bytes:
        """
        Get the public key as uncompressed bytes.
        
        Returns:
            65-byte uncompressed public key (0x04 || x || y)
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        
        return self._public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint
        )
    
    def get_public_key_hex(self) -> str:
        """Get the public key as hex string."""
        return self.get_public_key_bytes().hex()
    
    def get_private_key_hex(self) -> str:
        """Get the private key as hex string."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
        )
        
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).hex()
    
    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Compute shared secret from peer's public key.
        
        Args:
            peer_public_key_bytes: Peer's public key (65 bytes uncompressed)
        
        Returns:
            32-byte shared secret
        """
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key,
        )
        
        # Import the peer public key from DER
        # We need to convert uncompressed point to DER format
        peer_public_key = self._import_public_key(peer_public_key_bytes)
        
        shared_key = self._private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a clean 32-byte secret using HKDF
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"mingseal-ecdh-v1",
        ).derive(shared_key)
        
        return derived
    
    def _import_public_key(self, public_key_bytes: bytes):
        """
        Import a public key from bytes.
        
        Args:
            public_key_bytes: 65-byte uncompressed or 32-byte compressed
        
        Returns:
            EllipticCurvePublicKey
        """
        # For uncompressed (65 bytes starting with 0x04)
        if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            x = int.from_bytes(public_key_bytes[1:33], "big")
            y = int.from_bytes(public_key_bytes[33:65], "big")
            
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicKey,
                SECP256K1,
            )
            
            # Create public key using the point
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, SECP256K1())
            return public_numbers.public_key(default_backend())
        
        # For compressed (33 bytes starting with 0x02 or 0x03)
        elif len(public_key_bytes) == 33:
            return self._import_compressed_public_key(public_key_bytes)
        
        else:
            raise ValueError(f"Invalid public key length: {len(public_key_bytes)}")
    
    def _import_compressed_public_key(self, compressed: bytes):
        """Import a compressed public key."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers,
            SECP256K1,
        )
        
        prefix = compressed[0]
        x = int.from_bytes(compressed[1:33], "big")
        
        # Calculate y from x using curve equation y^2 = x^3 + 7
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_squared = (pow(x, 3, p) + 7) % p
        
        # Find square root
        y = pow(y_squared, (p + 1) // 4, p)
        
        # Choose correct y based on prefix
        if (y % 2) != (prefix - 2):
            y = p - y
        
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, SECP256K1())
        return public_numbers.public_key(default_backend())


def derive_shared_secret(
    private_key_hex: str,
    peer_public_key_hex: str,
) -> str:
    """
    Derive a shared secret between two parties.
    
    This is a convenience function for one-shot key exchange.
    
    Args:
        private_key_hex: Local private key
        peer_public_key_hex: Remote public key
    
    Returns:
        Hex-encoded shared secret
    """
    manager = ECDHKeyManager.from_private_key_hex(private_key_hex)
    peer_public = bytes.fromhex(peer_public_key_hex)
    shared = manager.compute_shared_secret(peer_public)
    return shared.hex()


def encrypt_with_shared_secret(
    shared_secret: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using a shared secret.
    
    Uses AES-256-GCM for authenticated encryption.
    
    Args:
        shared_secret: 32-byte shared secret
        plaintext: Data to encrypt
        associated_data: Optional additional authenticated data
    
    Returns:
        Tuple of (ciphertext, nonce)
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_secret[:32])
    
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        associated_data,
    )
    
    return ciphertext, nonce


def decrypt_with_shared_secret(
    shared_secret: bytes,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> Optional[bytes]:
    """
    Decrypt data using a shared secret.
    
    Args:
        shared_secret: 32-byte shared secret
        ciphertext: Encrypted data
        nonce: Nonce used during encryption
        associated_data: Optional additional authenticated data
    
    Returns:
        Decrypted plaintext, or None if decryption fails
    """
    try:
        aesgcm = AESGCM(shared_secret[:32])
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
        return plaintext
        
    except Exception as e:
        logger.debug(f"Decryption failed: {e}")
        return None


class SecureMessage:
    """
    Represents an encrypted message between agents.
    
    Format:
    - nonce (12 bytes)
    - ciphertext (variable)
    - tag (16 bytes, included in ciphertext)
    """
    
    def __init__(
        self,
        ciphertext: bytes,
        nonce: bytes,
        sender_public_key: bytes,
        recipient_public_key: bytes,
    ):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return (
            len(self.nonce).to_bytes(1, "big") +      # Nonce length
            self.nonce +
            len(self.sender_public_key).to_bytes(1, "big") +  # Sender key length
            self.sender_public_key +
            len(self.recipient_public_key).to_bytes(1, "big") +  # Recipient key length
            self.recipient_public_key +
            self.ciphertext
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureMessage":
        """Deserialize from bytes."""
        offset = 0
        
        # Read nonce
        nonce_len = data[offset]
        offset += 1
        nonce = data[offset:offset + nonce_len]
        offset += nonce_len
        
        # Read sender public key
        sender_len = data[offset]
        offset += 1
        sender_key = data[offset:offset + sender_len]
        offset += sender_len
        
        # Read recipient public key
        recipient_len = data[offset]
        offset += 1
        recipient_key = data[offset:offset + recipient_len]
        offset += recipient_len
        
        # Read ciphertext
        ciphertext = data[offset:]
        
        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            sender_public_key=sender_key,
            recipient_public_key=recipient_key,
        )
    
    def to_hex(self) -> str:
        """Serialize to hex string."""
        return self.to_bytes().hex()
    
    @classmethod
    def from_hex(cls, hex_data: str) -> "SecureMessage":
        """Deserialize from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_data))
