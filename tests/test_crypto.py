"""
Unit tests for the cryptographic utilities.
"""

import pytest
from mingseal_immutable_memory.crypto import (
    SigningKey,
    LocalSigner,
    compute_commitment,
    ECDHKeyManager,
    derive_shared_secret,
    encrypt_with_shared_secret,
    decrypt_with_shared_secret,
)


class TestSigningKey:
    """Tests for the SigningKey class."""
    
    def test_generate_key(self):
        """Test generating a new signing key."""
        key = SigningKey.generate()
        
        assert key.private_key_hex is not None
        assert key.public_key_hex is not None
        assert key.key_id is not None
        assert len(key.private_key_hex) > 0
        assert len(key.public_key_hex) > 0
    
    def test_key_id_is_hash_of_public(self):
        """Test that key ID is derived from public key."""
        key = SigningKey.generate()
        
        import hashlib
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_der_public_key,
        )
        
        public_der = bytes.fromhex(key.public_key_hex)
        
        # Key ID should be SHA-256 of public key DER bytes
        expected_id = hashlib.sha256(public_der).hexdigest()
        assert key.key_id == expected_id


class TestLocalSigner:
    """Tests for the LocalSigner class."""
    
    def test_initialization(self):
        """Test signer initialization."""
        signer = LocalSigner()
        
        assert signer.key_id is not None
        assert signer.public_key_hex is not None
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        signer = LocalSigner()
        
        data = b"Hello, World!"
        signature = signer.sign(data)
        
        assert signature is not None
        assert len(signature) > 0
        assert signer.verify(data, signature) is True
    
    def test_verify_wrong_signature(self):
        """Test verification with wrong signature."""
        signer = LocalSigner()
        
        data = b"Hello, World!"
        signature = signer.sign(data)
        
        # Tamper with signature
        wrong_signature = signature[:-4] + "xxxx"
        
        assert signer.verify(data, wrong_signature) is False
    
    def test_sign_text(self):
        """Test signing text content."""
        signer = LocalSigner()
        
        text = "Hello, World!"
        signature = signer.sign_text(text)
        
        assert signer.verify_text(text, signature) is True
    
    def test_create_commitment(self):
        """Test creating a commitment."""
        signer = LocalSigner()
        
        content = "Secret content"
        commitment, nonce = signer.create_commitment(content)
        
        assert commitment is not None
        assert nonce is not None
        assert len(commitment) == 64  # SHA-256 hex
    
    def test_verify_commitment(self):
        """Test verifying a commitment."""
        signer = LocalSigner()
        
        content = "Secret content"
        commitment, nonce = signer.create_commitment(content)
        
        assert signer.verify_commitment(content, commitment, nonce) is True
        assert signer.verify_commitment("Wrong content", commitment, nonce) is False


class TestComputeCommitment:
    """Tests for the compute_commitment function."""
    
    def test_commitment_creation(self):
        """Test creating a commitment."""
        content = "Test content"
        
        commitment, nonce = compute_commitment(content)
        
        assert commitment is not None
        assert nonce is not None
    
    def test_deterministic_with_same_nonce(self):
        """Test that same nonce produces same commitment."""
        content = "Test content"
        nonce = b"fixed_nonce_value"
        
        c1, n1 = compute_commitment(content, nonce)
        c2, n2 = compute_commitment(content, nonce)
        
        assert c1 == c2
        assert n1 == n2


class TestECDHKeyManager:
    """Tests for ECDH key exchange."""
    
    def test_generate_key_pair(self):
        """Test generating ECDH key pair."""
        manager = ECDHKeyManager()
        
        assert manager.get_public_key_hex() is not None
        assert manager.get_private_key_hex() is not None
    
    def test_public_key_format(self):
        """Test public key format."""
        manager = ECDHKeyManager()
        public_hex = manager.get_public_key_hex()
        
        # Should be uncompressed (65 bytes = 130 hex chars)
        assert len(public_hex) == 130
        assert public_hex.startswith("04")
    
    def test_shared_secret(self):
        """Test computing shared secret."""
        alice = ECDHKeyManager()
        bob = ECDHKeyManager()
        
        alice_public = alice.get_public_key_bytes()
        bob_public = bob.get_public_key_bytes()
        
        alice_secret = alice.compute_shared_secret(bob_public)
        bob_secret = bob.compute_shared_secret(alice_public)
        
        assert alice_secret == bob_secret
        assert len(alice_secret) == 32
    
    def test_different_keys_different_secret(self):
        """Test that different keys produce different secrets."""
        alice = ECDHKeyManager()
        bob1 = ECDHKeyManager()
        bob2 = ECDHKeyManager()
        
        alice_public = alice.get_public_key_bytes()
        
        secret1 = bob1.compute_shared_secret(alice_public)
        secret2 = bob2.compute_shared_secret(alice_public)
        
        assert secret1 != secret2


class TestDeriveSharedSecret:
    """Tests for the derive_shared_secret function."""
    
    def test_derive_shared_secret(self):
        """Test the derive_shared_secret convenience function."""
        alice = ECDHKeyManager()
        bob = ECDHKeyManager()
        
        secret1 = derive_shared_secret(
            alice.get_private_key_hex(),
            bob.get_public_key_hex(),
        )
        
        secret2 = derive_shared_secret(
            bob.get_private_key_hex(),
            alice.get_public_key_hex(),
        )
        
        assert secret1 == secret2


class TestEncryption:
    """Tests for symmetric encryption with shared secret."""
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        shared_secret = b"0" * 32  # 32 bytes
        plaintext = b"Secret message"
        
        ciphertext, nonce = encrypt_with_shared_secret(
            shared_secret, plaintext
        )
        
        assert ciphertext != plaintext
        assert nonce is not None
        
        decrypted = decrypt_with_shared_secret(
            shared_secret, ciphertext, nonce
        )
        
        assert decrypted == plaintext
    
    def test_decrypt_wrong_key(self):
        """Test decryption with wrong key."""
        shared_secret1 = b"0" * 32
        shared_secret2 = b"1" * 32
        
        plaintext = b"Secret message"
        
        ciphertext, nonce = encrypt_with_shared_secret(
            shared_secret1, plaintext
        )
        
        decrypted = decrypt_with_shared_secret(
            shared_secret2, ciphertext, nonce
        )
        
        assert decrypted is None
    
    def test_with_associated_data(self):
        """Test encryption with associated data."""
        shared_secret = b"0" * 32
        plaintext = b"Secret message"
        associated_data = b"Additional authenticated data"
        
        ciphertext, nonce = encrypt_with_shared_secret(
            shared_secret, plaintext, associated_data
        )
        
        # Decryption with correct associated data
        decrypted = decrypt_with_shared_secret(
            shared_secret, ciphertext, nonce, associated_data
        )
        assert decrypted == plaintext
        
        # Decryption without associated data should fail
        decrypted_no_aad = decrypt_with_shared_secret(
            shared_secret, ciphertext, nonce
        )
        assert decrypted_no_aad is None
