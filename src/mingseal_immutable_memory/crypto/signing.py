"""
Local Signing and Commitment.

Provides local signing capabilities for agent identity verification
and content commitment. This is used for Layer 3 (ECDH encryption)
preparation and optional agent signatures on transitions.
"""

import hashlib
import hmac
import os
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class SigningKey:
    """
    Represents a signing key pair for agent identity.
    
    This is a lightweight key implementation for local signing.
    For production use with actual agent identity, consider using
    proper key management systems.
    """
    private_key_hex: str
    public_key_hex: str
    key_id: str  # SHA-256 of public key
    
    @classmethod
    def generate(cls) -> "SigningKey":
        """
        Generate a new signing key pair.
        
        Returns:
            A new SigningKey instance
        """
        private_key = ec.generate_private_key(
            ec.SECP256K1(),
            default_backend()
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_hex = private_pem.hex()
        public_hex = public_der.hex()
        key_id = hashlib.sha256(public_der).hexdigest()
        
        return cls(
            private_key_hex=private_hex,
            public_key_hex=public_hex,
            key_id=key_id,
        )
    
    @classmethod
    def from_hex(cls, private_key_hex: str) -> "SigningKey":
        """
        Load a signing key from hex-encoded private key.
        
        Args:
            private_key_hex: Hex-encoded private key
        
        Returns:
            A SigningKey instance
        """
        private_pem = bytes.fromhex(private_key_hex)
        private_key = serialization.load_der_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_hex = public_der.hex()
        key_id = hashlib.sha256(public_der).hexdigest()
        
        return cls(
            private_key_hex=private_key_hex,
            public_key_hex=public_hex,
            key_id=key_id,
        )
    
    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Get the cryptography private key object."""
        private_pem = bytes.fromhex(self.private_key_hex)
        return serialization.load_der_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
    
    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        """Get the cryptography public key object."""
        public_der = bytes.fromhex(self.public_key_hex)
        # Load as PEM with DER wrapper
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        return load_der_public_key(public_der, default_backend())


class LocalSigner:
    """
    Local signing service for agent transitions and commitments.
    
    Uses ECDSA with SECP256K1 for signatures. This provides:
    - Agent identity verification
    - Content commitment (non-repudiation)
    - Layer 3 ECDH key exchange preparation
    """
    
    def __init__(self, signing_key: Optional[SigningKey] = None):
        """
        Initialize local signer.
        
        Args:
            signing_key: Optional signing key (generated if not provided)
        """
        self._signing_key = signing_key or SigningKey.generate()
        logger.info(f"LocalSigner initialized with key ID: {self._signing_key.key_id[:16]}...")
    
    @property
    def key_id(self) -> str:
        """Get the signer's key ID."""
        return self._signing_key.key_id
    
    @property
    def public_key_hex(self) -> str:
        """Get the public key in hex format."""
        return self._signing_key.public_key_hex
    
    def sign(self, data: bytes) -> str:
        """
        Sign data with the agent's private key.
        
        Args:
            data: Data to sign
        
        Returns:
            Hex-encoded signature
        """
        private_key = self._signing_key.get_private_key()
        
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature.hex()
    
    def sign_text(self, text: str) -> str:
        """
        Sign text content.
        
        Args:
            text: Text to sign
        
        Returns:
            Hex-encoded signature
        """
        data = text.encode("utf-8")
        return self.sign(data)
    
    def verify(self, data: bytes, signature_hex: str) -> bool:
        """
        Verify a signature.
        
        Args:
            data: Original data
            signature_hex: Hex-encoded signature
        
        Returns:
            True if signature is valid
        """
        try:
            signature = bytes.fromhex(signature_hex)
            public_key = self._signing_key.get_public_key()
            
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False
    
    def verify_text(self, text: str, signature_hex: str) -> bool:
        """
        Verify a text signature.
        
        Args:
            text: Original text
            signature_hex: Hex-encoded signature
        
        Returns:
            True if signature is valid
        """
        data = text.encode("utf-8")
        return self.verify(data, signature_hex)
    
    def sign_transition(self, transition_data: bytes) -> str:
        """
        Sign a transition for non-repudiation.
        
        Args:
            transition_data: Serialized transition bytes
        
        Returns:
            Hex-encoded signature
        """
        # Include key ID in signed data for verification
        signed_data = self._signing_key.key_id.encode() + transition_data
        return self.sign(signed_data)
    
    def create_commitment(self, content: str, nonce: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Create a commitment (hash-locked value).
        
        This is useful for committing to content before revealing it.
        
        Args:
            content: Content to commit to
            nonce: Optional nonce (random if not provided)
        
        Returns:
            Tuple of (commitment_hash, nonce)
        """
        if nonce is None:
            nonce = os.urandom(32)
        
        data = content.encode() + nonce
        commitment = hashlib.sha256(data).hexdigest()
        
        return commitment, nonce.hex()
    
    def verify_commitment(
        self,
        content: str,
        commitment: str,
        nonce_hex: str,
    ) -> bool:
        """
        Verify a commitment.
        
        Args:
            content: Content that was committed
            commitment: The commitment hash
            nonce_hex: The nonce used in commitment
        
        Returns:
            True if commitment is valid
        """
        nonce = bytes.fromhex(nonce_hex)
        data = content.encode() + nonce
        expected = hashlib.sha256(data).hexdigest()
        
        return hmac.compare_digest(commitment, expected)


def compute_commitment(content: str, nonce: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Compute a commitment hash for content.
    
    This is a convenience function that doesn't require a signer instance.
    
    Args:
        content: Content to commit to
        nonce: Optional nonce
    
    Returns:
        Tuple of (commitment_hash, nonce_hex)
    """
    if nonce is None:
        nonce = os.urandom(32)
    
    data = content.encode() + nonce
    commitment = hashlib.sha256(data).hexdigest()
    
    return commitment, nonce.hex()


class CommitmentStore:
    """
    Store and verify commitments.
    
    Useful for multi-round protocols where one party commits
    to a value and reveals it later.
    """
    
    def __init__(self):
        self._commitments: dict[str, dict] = {}
    
    def commit(self, content: str, context: Optional[str] = None) -> Tuple[str, str]:
        """
        Create and store a commitment.
        
        Args:
            content: Content to commit
            context: Optional context identifier
        
        Returns:
            Tuple of (commitment_id, nonce_hex)
        """
        commitment, nonce = compute_commitment(content)
        
        commitment_id = hashlib.sha256(
            f"{commitment}:{context or ''}".encode()
        ).hexdigest()[:16]
        
        self._commitments[commitment_id] = {
            "content": content,
            "commitment": commitment,
            "nonce": nonce,
            "context": context,
        }
        
        return commitment_id, nonce
    
    def reveal(self, commitment_id: str) -> Optional[str]:
        """
        Get the committed content after reveal.
        
        Args:
            commitment_id: The commitment ID
        
        Returns:
            The original content, or None if not found
        """
        commitment = self._commitments.get(commitment_id)
        return commitment["content"] if commitment else None
    
    def verify(self, commitment_id: str, content: str) -> bool:
        """
        Verify revealed content matches the commitment.
        
        Args:
            commitment_id: The commitment ID
            content: The content to verify
        
        Returns:
            True if content matches the commitment
        """
        commitment = self._commitments.get(commitment_id)
        if not commitment:
            return False
        
        expected = hashlib.sha256(content.encode() + bytes.fromhex(commitment["nonce"])).hexdigest()
        return hmac.compare_digest(commitment["commitment"], expected)
