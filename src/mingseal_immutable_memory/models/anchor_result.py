"""
Anchor Result and Verification data models.

Represents the results of anchoring operations and verification checks.
Supports multiple backend types: Local Sign, OpenTimestamps, and BSV.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class AnchorBackend(str, Enum):
    """Supported anchoring backend types."""
    LOCAL = "local"
    OTS = "ots"
    BSV = "bsv"


class AnchorCapability(BaseModel):
    """Describes the capabilities of an anchoring backend."""
    backend: AnchorBackend
    name: str
    description: str
    third_party_verifiable: bool = False
    requires_network: bool = False
    requires_payment: bool = False
    estimated_cost_usd: Optional[float] = None
    avg_confirmation_time: Optional[str] = None  # e.g., "10 minutes", "1 block"


class AnchorResult(BaseModel):
    """
    Result of an anchoring operation.
    
    Contains all information needed to verify the anchored data
    and retrieve the proof from the blockchain/anchor service.
    """
    anchor_id: str = Field(..., description="Unique anchor identifier")
    backend: AnchorBackend = Field(..., description="Backend used for anchoring")
    merkle_root: str = Field(..., description="The Merkle root that was anchored")
    tx_id: Optional[str] = Field(None, description="Blockchain transaction ID (bsv/ots)")
    timestamp: str = Field(..., description="ISO8601 timestamp of anchoring")
    block_height: Optional[int] = Field(None, description="Block height (if applicable)")
    verified: bool = Field(default=False, description="Whether verification passed")
    proof_data: dict = Field(default_factory=dict, description="Backend-specific proof data")
    error: Optional[str] = Field(None, description="Error message if anchoring failed")
    
    def to_ots_format(self) -> dict:
        """Convert to OpenTimestamps-compatible format."""
        return {
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "tx_id": self.tx_id,
            "verified": self.verified,
        }
    
    def to_bsv_format(self) -> dict:
        """Convert to BSV OP_RETURN format details."""
        return {
            "anchor_id": self.anchor_id,
            "merkle_root": self.merkle_root,
            "tx_id": self.tx_id,
            "block_height": self.block_height,
            "timestamp": self.timestamp,
        }


class VerifyResult(BaseModel):
    """
    Result of a verification operation.
    
    Contains detailed verification status and any issues found.
    """
    verified: bool = Field(..., description="Overall verification status")
    anchor_id: str = Field(..., description="Anchor ID being verified")
    merkle_root: str = Field(..., description="Merkle root being verified")
    
    # Verification components
    hash_integrity: bool = Field(default=True, description="Content hash matches")
    merkle_inclusion: bool = Field(default=True, description="Merkle proof is valid")
    anchor_valid: bool = Field(default=True, description="Anchor is valid/confirmed")
    chain_confirmed: bool = Field(default=False, description="Confirmed on chain")
    
    # Details
    merkle_proof_valid: bool = Field(default=True, description="Merkle proof structure valid")
    anchor_timestamp: Optional[str] = Field(None, description="When anchor was confirmed")
    block_height: Optional[int] = Field(None, description="Block height if confirmed")
    tx_id: Optional[str] = Field(None, description="Transaction ID if on-chain")
    
    # Warnings and errors
    warnings: List[str] = Field(default_factory=list, description="Non-critical issues")
    errors: List[str] = Field(default_factory=list, description="Critical errors")
    
    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)
    
    def add_error(self, message: str) -> None:
        """Add an error message and mark as failed."""
        self.errors.append(message)
        self.verified = False


class BatchAnchorRequest(BaseModel):
    """Request to anchor a batch of transitions."""
    transition_ids: List[str] = Field(..., description="IDs of transitions to anchor")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")
    force: bool = Field(default=False, description="Force anchoring even if recent")


class BatchAnchorResult(BaseModel):
    """Result of a batch anchoring operation."""
    batch_id: str = Field(..., description="Unique batch identifier")
    merkle_root: str = Field(..., description="Root of the Merkle tree")
    merkle_tree: dict = Field(..., description="Merkle tree structure for proofs")
    transitions_count: int = Field(..., description="Number of transitions anchored")
    anchor_result: AnchorResult = Field(..., description="The anchoring result")
    node_ids: List[str] = Field(default_factory=list, description="Created memory node IDs")


def create_anchor_result(
    backend: AnchorBackend,
    merkle_root: str,
    tx_id: Optional[str] = None,
    error: Optional[str] = None,
) -> AnchorResult:
    """
    Factory function to create an anchor result.
    
    Args:
        backend: The anchoring backend used
        merkle_root: The Merkle root that was anchored
        tx_id: Transaction ID (for on-chain backends)
        error: Error message if anchoring failed
    
    Returns:
        A new AnchorResult instance
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Generate anchor ID
    import hashlib
    anchor_id_data = f"{backend.value}:{merkle_root}:{timestamp}".encode("utf-8")
    anchor_id = "anc_" + hashlib.sha256(anchor_id_data).hexdigest()[:16]
    
    return AnchorResult(
        anchor_id=anchor_id,
        backend=backend,
        merkle_root=merkle_root,
        tx_id=tx_id,
        timestamp=timestamp,
        verified=error is None,
        error=error,
    )
