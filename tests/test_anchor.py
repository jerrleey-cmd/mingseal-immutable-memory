"""
Unit tests for the anchoring backends.
"""

import pytest
from mingseal_immutable_memory.core.anchor import (
    LocalSignAnchor,
    OpenTimestampsAnchor,
    BSVAnchor,
    get_anchor_backend,
    list_available_backends,
)
from mingseal_immutable_memory.models.anchor_result import AnchorBackend


class TestLocalSignAnchor:
    """Tests for the LocalSignAnchor backend."""
    
    @pytest.fixture
    def anchor(self):
        """Create a LocalSignAnchor instance."""
        return LocalSignAnchor()
    
    @pytest.mark.asyncio
    async def test_anchor(self, anchor):
        """Test anchoring a Merkle root."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        
        assert result.anchor_id is not None
        assert result.backend == AnchorBackend.LOCAL
        assert result.merkle_root == merkle_root.hex()
        assert result.verified is True
        assert "signature" in result.proof_data
    
    @pytest.mark.asyncio
    async def test_verify_valid(self, anchor):
        """Test verifying a valid anchor."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        anchor_result = await anchor.anchor(merkle_root, {})
        verify_result = await anchor.verify(merkle_root, anchor_result.anchor_id)
        
        assert verify_result.verified is True
        assert verify_result.anchor_valid is True
    
    @pytest.mark.asyncio
    async def test_verify_invalid_root(self, anchor):
        """Test verification fails with wrong root."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        wrong_root = b"wrong_merkle_root_32_bytes____"
        
        anchor_result = await anchor.anchor(merkle_root, {})
        verify_result = await anchor.verify(wrong_root, anchor_result.anchor_id)
        
        assert verify_result.verified is False
    
    @pytest.mark.asyncio
    async def test_verify_nonexistent(self, anchor):
        """Test verification of nonexistent anchor."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        verify_result = await anchor.verify(merkle_root, "nonexistent_id")
        
        assert verify_result.verified is False
        assert len(verify_result.errors) > 0
    
    def test_capability(self, anchor):
        """Test getting backend capabilities."""
        cap = anchor.capability()
        
        assert cap.backend == AnchorBackend.LOCAL
        assert cap.name == "Local Sign"
        assert cap.third_party_verifiable is False
        assert cap.requires_network is False
        assert cap.requires_payment is False
        assert cap.estimated_cost_usd == 0.0


class TestOpenTimestampsAnchor:
    """Tests for the OpenTimestampsAnchor backend."""
    
    @pytest.fixture
    def anchor(self):
        """Create an OpenTimestampsAnchor instance."""
        return OpenTimestampsAnchor()
    
    @pytest.mark.asyncio
    async def test_anchor(self, anchor):
        """Test submitting to OTS (mock)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        
        assert result.anchor_id is not None
        assert result.backend == AnchorBackend.OTS
        assert result.tx_id is not None
    
    @pytest.mark.asyncio
    async def test_verify_pending(self, anchor):
        """Test verifying a pending anchor (mock)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        verify_result = await anchor.verify(merkle_root, result.anchor_id)
        
        # Pending anchors should not be fully verified
        assert verify_result.verified is True  # No error, just pending
        assert verify_result.chain_confirmed is False
    
    def test_capability(self, anchor):
        """Test getting backend capabilities."""
        cap = anchor.capability()
        
        assert cap.backend == AnchorBackend.OTS
        assert cap.name == "OpenTimestamps"
        assert cap.third_party_verifiable is True
        assert cap.requires_network is True
        assert cap.requires_payment is False


class TestBSVAnchor:
    """Tests for the BSVAnchor backend."""
    
    @pytest.fixture
    def anchor(self):
        """Create a BSVAnchor instance (mock mode - no key)."""
        return BSVAnchor(network="test")
    
    @pytest.fixture
    def mock_anchor(self):
        """Create a BSVAnchor with explicit mock mode."""
        return BSVAnchor(private_key_hex=None, network="test")
    
    @pytest.mark.asyncio
    async def test_anchor_mock_mode(self, anchor):
        """Test BSV anchoring in mock mode (no wallet)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        
        assert result.anchor_id is not None
        assert result.backend == AnchorBackend.BSV
        assert "op_return_hex" in result.proof_data
        assert result.proof_data.get("mode") == "mock"
    
    @pytest.mark.asyncio
    async def test_anchor_op_return_format(self, anchor):
        """Test that OP_RETURN data has correct MSLL format."""
        # Use a 32-byte merkle root (properly padded if needed)
        merkle_root = b"test_merkle_root_32_bytes_da"  # 31 bytes, will be padded to 32
        
        result = await anchor.anchor(merkle_root, {})
        
        op_return_hex = result.proof_data.get("op_return_hex", "")
        op_return_bytes = bytes.fromhex(op_return_hex)
        
        # Check total minimum length (4 + 1 + 32 + 4 + 20 + 64 = 125)
        assert len(op_return_bytes) >= 125, f"OP_RETURN data too short: {len(op_return_bytes)} bytes"
        
        # Check MSLL magic
        assert op_return_bytes[:4] == b"MSLL", "Missing MSLL magic bytes"
        # Check version
        assert op_return_bytes[4] == 2, "Wrong version byte"
        # Check epoch (4 bytes after merkle_root starts at byte 37)
        epoch = int.from_bytes(op_return_bytes[37:41], "little")
        assert epoch > 0, "Invalid epoch"
        # Check agent_pk_hash (20 bytes after epoch)
        assert len(op_return_bytes[41:61]) == 20, "Invalid agent_pk_hash length"
        # Check signature exists (rest)
        assert len(op_return_bytes[61:]) > 0, "Missing signature"
    
    @pytest.mark.asyncio
    async def test_verify_mock(self, anchor):
        """Test verifying BSV anchor (mock mode)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        verify_result = await anchor.verify(merkle_root, result.anchor_id)
        
        # Mock BSV anchor should be verified with warning
        assert verify_result.verified is True
        assert verify_result.anchor_valid is True
        assert any("Mock" in w for w in verify_result.warnings), "Expected mock warning"
    
    @pytest.mark.asyncio
    async def test_verify_nonexistent(self, anchor):
        """Test verification of nonexistent anchor."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        verify_result = await anchor.verify(merkle_root, "nonexistent_id")
        
        assert verify_result.verified is False
        assert len(verify_result.errors) > 0
    
    def test_capability(self, anchor):
        """Test getting backend capabilities."""
        cap = anchor.capability()
        
        assert cap.backend == AnchorBackend.BSV
        assert cap.name == "BSV OP_RETURN"
        assert cap.third_party_verifiable is True
        assert cap.requires_network is True
        assert cap.requires_payment is True


class TestBackendRegistry:
    """Tests for the backend registry."""
    
    def test_get_anchor_backend_local(self):
        """Test getting local anchor backend."""
        backend = get_anchor_backend(AnchorBackend.LOCAL)
        
        assert isinstance(backend, LocalSignAnchor)
    
    def test_get_anchor_backend_ots(self):
        """Test getting OTS anchor backend."""
        backend = get_anchor_backend(AnchorBackend.OTS)
        
        assert isinstance(backend, OpenTimestampsAnchor)
    
    def test_get_anchor_backend_bsv(self):
        """Test getting BSV anchor backend."""
        backend = get_anchor_backend(AnchorBackend.BSV)
        
        assert isinstance(backend, BSVAnchor)
    
    def test_list_available_backends(self):
        """Test listing all available backends."""
        backends = list_available_backends()
        
        assert len(backends) == 3
        backends_by_type = {b.backend for b in backends}
        assert AnchorBackend.LOCAL in backends_by_type
        assert AnchorBackend.OTS in backends_by_type
        assert AnchorBackend.BSV in backends_by_type
