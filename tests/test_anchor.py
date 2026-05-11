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
        """Create a BSVAnchor instance."""
        return BSVAnchor(network="test")
    
    @pytest.mark.asyncio
    async def test_anchor(self, anchor):
        """Test BSV anchoring (mock)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        
        assert result.anchor_id is not None
        assert result.backend == AnchorBackend.BSV
        assert "op_return_hex" in result.proof_data
    
    @pytest.mark.asyncio
    async def test_verify(self, anchor):
        """Test verifying BSV anchor (mock)."""
        merkle_root = b"test_merkle_root_32_bytes_data_"
        
        result = await anchor.anchor(merkle_root, {})
        verify_result = await anchor.verify(merkle_root, result.anchor_id)
        
        # Mock BSV anchor should be verified
        assert verify_result.verified is True
        assert verify_result.anchor_valid is True
    
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
