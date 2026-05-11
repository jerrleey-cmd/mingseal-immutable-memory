"""
Layer 4: Pluggable Anchoring Backends.

Provides abstraction for different anchoring strategies:
- Level 0: Local Sign (HMAC-SHA256)
- Level 1: OpenTimestamps (BTC)
- Level 2: BSV OP_RETURN

Each backend implements the same interface but provides different
trade-offs in terms of cost, trust, and third-party verifiability.
"""

import hashlib
import hmac
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any

from ..models.anchor_result import (
    AnchorBackend,
    AnchorCapability,
    AnchorResult,
    VerifyResult,
    create_anchor_result,
)

logger = logging.getLogger(__name__)


class AnchorBackendInterface(ABC):
    """
    Abstract base class for anchoring backends.
    
    All backends must implement these methods to ensure
    consistent behavior across different anchoring strategies.
    """
    
    @abstractmethod
    async def anchor(self, merkle_root: bytes, metadata: Dict[str, Any]) -> AnchorResult:
        """
        Anchor a Merkle root to the backend.
        
        Args:
            merkle_root: The Merkle root to anchor (32 bytes or hex string)
            metadata: Additional metadata for the anchor
        
        Returns:
            AnchorResult with anchoring details
        """
        pass
    
    @abstractmethod
    async def verify(self, merkle_root: bytes, anchor_id: str) -> VerifyResult:
        """
        Verify an anchored Merkle root.
        
        Args:
            merkle_root: The Merkle root to verify
            anchor_id: The anchor ID returned from anchoring
        
        Returns:
            VerifyResult with verification details
        """
        pass
    
    @abstractmethod
    def capability(self) -> AnchorCapability:
        """
        Get the capabilities of this backend.
        
        Returns:
            AnchorCapability describing this backend
        """
        pass


class LocalSignAnchor(AnchorBackendInterface):
    """
    Level 0: Local Signature Commitment.
    
    Uses HMAC-SHA256 to sign the Merkle root with a local key.
    - Cost: Free
    - Network: Not required
    - Third-party verifiable: No (local key only)
    - Security: Key-dependent only
    
    This is useful for:
    - Development and testing
    - Internal integrity verification
    - Situations where local-only proof is acceptable
    """
    
    def __init__(self, signing_key: Optional[bytes] = None):
        """
        Initialize local sign anchor.
        
        Args:
            signing_key: HMAC key (generated if not provided)
        """
        if signing_key:
            self._key = signing_key
        else:
            self._key = self._generate_key()
        
        self._anchors: Dict[str, AnchorResult] = {}
    
    def _generate_key(self) -> bytes:
        """Generate a random HMAC key."""
        return os.urandom(32)
    
    def _sign(self, merkle_root: bytes) -> str:
        """Create HMAC signature of Merkle root."""
        if isinstance(merkle_root, str):
            merkle_root = merkle_root.encode()
        signature = hmac.new(self._key, merkle_root, hashlib.sha256).hexdigest()
        return signature
    
    async def anchor(self, merkle_root: bytes, metadata: Dict[str, Any]) -> AnchorResult:
        """
        Anchor using local HMAC signature.
        
        Creates a commitment proof that can verify integrity
        but cannot be verified by third parties.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        # Create signature
        signature = self._sign(merkle_root)
        
        # Create anchor result
        result = create_anchor_result(
            backend=AnchorBackend.LOCAL,
            merkle_root=merkle_root_hex,
            tx_id=None,
        )
        
        # Store for verification
        self._anchors[result.anchor_id] = result
        result.proof_data = {
            "signature": signature,
            "key_id": hashlib.sha256(self._key).hexdigest()[:16],
            "algorithm": "HMAC-SHA256",
        }
        result.verified = True
        
        logger.info(f"Local anchor created: {result.anchor_id}")
        
        return result
    
    async def verify(self, merkle_root: bytes, anchor_id: str) -> VerifyResult:
        """
        Verify a local anchor.
        
        Checks that the signature matches and the Merkle root
        was committed with this backend's key.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        result = VerifyResult(
            verified=False,
            anchor_id=anchor_id,
            merkle_root=merkle_root_hex,
        )
        
        # Find the anchor
        anchor = self._anchors.get(anchor_id)
        if not anchor:
            result.add_error(f"Anchor {anchor_id} not found")
            return result
        
        # Verify signature
        signature = anchor.proof_data.get("signature")
        if not signature:
            result.add_error("No signature in anchor")
            return result
        
        expected_signature = self._sign(merkle_root)
        if signature != expected_signature:
            result.add_error("Signature mismatch")
            return result
        
        # All checks passed
        result.verified = True
        result.anchor_valid = True
        result.hash_integrity = True
        result.merkle_inclusion = True
        result.anchor_timestamp = anchor.timestamp
        
        logger.info(f"Local anchor verified: {anchor_id}")
        
        return result
    
    def capability(self) -> AnchorCapability:
        """Get backend capabilities."""
        return AnchorCapability(
            backend=AnchorBackend.LOCAL,
            name="Local Sign",
            description="Local HMAC-SHA256 signature commitment. Free but not third-party verifiable.",
            third_party_verifiable=False,
            requires_network=False,
            requires_payment=False,
            estimated_cost_usd=0.0,
            avg_confirmation_time="Instant",
        )


class OpenTimestampsAnchor(AnchorBackendInterface):
    """
    Level 1: OpenTimestamps Proof.
    
    Uses the OpenTimestamps protocol to create a Bitcoin timestamp.
    - Cost: Free (uses public calendar servers)
    - Network: Required
    - Third-party verifiable: Yes (BTC blockchain)
    - Security: Depends on BTC network
    
    Note: This implementation provides the interface and mock functionality.
    Actual OTS integration requires:
    - Connection to OTS calendar servers
    - Bitcoin blockchain for final proof
    """
    
    def __init__(self, calendar_urls: Optional[list] = None):
        """
        Initialize OpenTimestamps anchor.
        
        Args:
            calendar_urls: List of OTS calendar server URLs
        """
        self._calendar_urls = calendar_urls or [
            "https://www.ots.cdf.ericsson.net"
        ]
        self._pending_anchors: Dict[str, AnchorResult] = {}
        self._confirmed_anchors: Dict[str, AnchorResult] = {}
    
    async def anchor(self, merkle_root: bytes, metadata: Dict[str, Any]) -> AnchorResult:
        """
        Submit Merkle root to OpenTimestamps calendar.
        
        This creates a pending timestamp that will be included
        in a future Bitcoin block.
        
        Note: In production, this would:
        1. Connect to OTS calendar server
        2. Submit the merkle_root
        3. Receive an OTS proof file
        4. Wait for BTC block inclusion
        
        Current implementation is a mock.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        # Create pending anchor (mock)
        result = create_anchor_result(
            backend=AnchorBackend.OTS,
            merkle_root=merkle_root_hex,
            tx_id=f"ots_pending_{hashlib.sha256(merkle_root).hexdigest()[:16]}",
        )
        
        result.proof_data = {
            "calendar_url": self._calendar_urls[0],
            "ots_format": "pending",
            "note": "Mock OTS - actual integration requires BTC connection",
            "submit_timestamp": datetime.utcnow().isoformat() + "Z",
        }
        
        self._pending_anchors[result.anchor_id] = result
        
        logger.info(f"OTS anchor submitted: {result.anchor_id}")
        
        return result
    
    async def verify(self, merkle_root: bytes, anchor_id: str) -> VerifyResult:
        """
        Verify an OpenTimestamps anchor.
        
        Note: In production, this would:
        1. Retrieve OTS proof file
        2. Verify against BTC blockchain
        3. Return block timestamp
        
        Current implementation is a mock.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        result = VerifyResult(
            verified=False,
            anchor_id=anchor_id,
            merkle_root=merkle_root_hex,
        )
        
        # Check pending anchors
        anchor = self._pending_anchors.get(anchor_id)
        if anchor:
            result.add_warning("OTS anchor is pending - not yet confirmed on BTC")
            result.verified = True  # Pending is not failure
            result.anchor_valid = True
            result.anchor_timestamp = anchor.timestamp
            return result
        
        # Check confirmed anchors
        anchor = self._confirmed_anchors.get(anchor_id)
        if not anchor:
            result.add_error(f"Anchor {anchor_id} not found")
            return result
        
        result.verified = True
        result.anchor_valid = True
        result.chain_confirmed = True
        result.anchor_timestamp = anchor.timestamp
        result.tx_id = anchor.tx_id
        result.block_height = anchor.block_height
        
        return result
    
    def capability(self) -> AnchorCapability:
        """Get backend capabilities."""
        return AnchorCapability(
            backend=AnchorBackend.OTS,
            name="OpenTimestamps",
            description="Bitcoin timestamp via OpenTimestamps protocol. Free, third-party verifiable via BTC.",
            third_party_verifiable=True,
            requires_network=True,
            requires_payment=False,
            estimated_cost_usd=0.0,
            avg_confirmation_time="Hours to days",
        )


class BSVAnchor(AnchorBackendInterface):
    """
    Level 2: BSV OP_RETURN Anchoring.
    
    Writes directly to BSV blockchain with OP_RETURN.
    - Cost: BSV transaction fees
    - Network: Required (BSV)
    - Third-party verifiable: Yes (BSV blockchain)
    - Security: Full blockchain security with OP_RETURN data
    
    Format: MSLL | v2 | root(32B) | epoch | agent_pk_hash | signature
    
    Note: This implementation provides the interface and mock functionality.
    Actual BSV integration requires:
    - BSV wallet with funds
    - Connection to BSV network
    - Transaction construction and signing
    """
    
    MSLL_MAGIC = b"MSLL"
    VERSION = 2
    
    def __init__(self, wif_key: Optional[str] = None, network: str = "main"):
        """
        Initialize BSV anchor.
        
        Args:
            wif_key: BSV private key in WIF format
            network: Network type ("main" or "test")
        """
        self._wif_key = wif_key
        self._network = network
        self._anchors: Dict[str, AnchorResult] = {}
        
        if not wif_key:
            logger.warning("No BSV WIF key provided - using mock mode")
    
    def _construct_op_return(self, merkle_root: bytes, metadata: Dict[str, Any]) -> bytes:
        """
        Construct BSV OP_RETURN data.
        
        Format:
        - MSLL (4 bytes) - Magic bytes
        - version (1 byte) - Protocol version
        - merkle_root (32 bytes) - The anchored root
        - epoch (4 bytes) - Unix timestamp / 512
        - agent_pk_hash (20 bytes) - Hash of agent public key
        - signature (64 bytes) - Signature of the above data
        """
        merkle_root_bytes = merkle_root if isinstance(merkle_root, bytes) else bytes.fromhex(merkle_root)
        
        # Compute epoch (simplified)
        epoch = int(datetime.utcnow().timestamp()) // 512
        
        # Agent PK hash (mock if no key provided)
        if self._wif_key:
            agent_pk_hash = hashlib.new("ripemd160", self._wif_key.encode()).digest()[:20]
        else:
            agent_pk_hash = bytes(20)
        
        # Build data
        data = bytearray()
        data.extend(self.MSLL_MAGIC)
        data.append(self.VERSION)
        data.extend(merkle_root_bytes[:32])
        data.extend(epoch.to_bytes(4, "little"))
        data.extend(agent_pk_hash)
        
        # Signature placeholder (would be computed with actual key)
        if self._wif_key:
            signature = hashlib.sha256(bytes(data) + self._wif_key.encode()).digest()
        else:
            signature = bytes(64)
        data.extend(signature)
        
        return bytes(data)
    
    async def anchor(self, merkle_root: bytes, metadata: Dict[str, Any]) -> AnchorResult:
        """
        Anchor to BSV blockchain.
        
        Note: In production, this would:
        1. Construct OP_RETURN transaction
        2. Sign with BSV private key
        3. Broadcast to BSV network
        4. Wait for confirmation
        
        Current implementation is a mock.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        # Construct OP_RETURN data
        op_return_data = self._construct_op_return(merkle_root, metadata)
        
        # Create mock transaction ID
        tx_id = hashlib.sha256(op_return_data + datetime.utcnow().isoformat().encode()).hexdigest()
        
        result = create_anchor_result(
            backend=AnchorBackend.BSV,
            merkle_root=merkle_root_hex,
            tx_id=f"bsv_{tx_id[:16]}",
        )
        
        result.proof_data = {
            "op_return_hex": op_return_data.hex(),
            "network": self._network,
            "note": "Mock BSV - actual integration requires BSV wallet and network",
            "block_height": None,  # Would be set after confirmation
        }
        
        self._anchors[result.anchor_id] = result
        
        logger.info(f"BSV anchor created (mock): {result.anchor_id}")
        
        return result
    
    async def verify(self, merkle_root: bytes, anchor_id: str) -> VerifyResult:
        """
        Verify a BSV anchor.
        
        Note: In production, this would:
        1. Query BSV blockchain for transaction
        2. Verify OP_RETURN data matches
        3. Return block information
        
        Current implementation is a mock.
        """
        merkle_root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        
        result = VerifyResult(
            verified=False,
            anchor_id=anchor_id,
            merkle_root=merkle_root_hex,
        )
        
        anchor = self._anchors.get(anchor_id)
        if not anchor:
            result.add_error(f"Anchor {anchor_id} not found")
            return result
        
        # Verify Merkle root matches
        if anchor.merkle_root != merkle_root_hex:
            result.add_error("Merkle root mismatch")
            return result
        
        result.verified = True
        result.anchor_valid = True
        result.chain_confirmed = True  # Mock always confirmed
        result.anchor_timestamp = anchor.timestamp
        result.tx_id = anchor.tx_id
        result.block_height = 850000  # Mock block height
        
        return result
    
    def capability(self) -> AnchorCapability:
        """Get backend capabilities."""
        return AnchorCapability(
            backend=AnchorBackend.BSV,
            name="BSV OP_RETURN",
            description="Direct BSV blockchain anchoring with OP_RETURN. Full司法存证 capability.",
            third_party_verifiable=True,
            requires_network=True,
            requires_payment=True,
            estimated_cost_usd=0.0001,  # Approximate BSV fee
            avg_confirmation_time="1 block (~10 minutes)",
        )


# Backend registry
_BACKENDS = {
    AnchorBackend.LOCAL: LocalSignAnchor,
    AnchorBackend.OTS: OpenTimestampsAnchor,
    AnchorBackend.BSV: BSVAnchor,
}


def get_anchor_backend(backend_type: AnchorBackend, **kwargs) -> AnchorBackendInterface:
    """
    Get an anchoring backend by type.
    
    Args:
        backend_type: The type of backend to create
        **kwargs: Arguments to pass to the backend constructor
    
    Returns:
        An instance of the requested backend
    """
    backend_class = _BACKENDS.get(backend_type)
    if not backend_class:
        raise ValueError(f"Unknown backend type: {backend_type}")
    
    return backend_class(**kwargs)


def list_available_backends() -> list[AnchorCapability]:
    """List all available anchoring backends and their capabilities."""
    capabilities = []
    
    for backend_type in AnchorBackend:
        backend = get_anchor_backend(backend_type)
        capabilities.append(backend.capability())
    
    return capabilities
