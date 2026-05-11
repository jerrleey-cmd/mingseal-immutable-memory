"""Core modules for MingSeal Immutable Memory."""

from .transition import Transition, TransitionStore, create_transition, compute_content_hash
from .dag import MemoryDAG, CycleDetectedError
from .merkle import MerkleTree, MerkleProof
from .anchor import (
    AnchorBackend,
    AnchorCapability,
    AnchorResult,
    VerifyResult,
    LocalSignAnchor,
    OpenTimestampsAnchor,
    BSVAnchor,
    get_anchor_backend,
)
from .verification import VerificationEngine, VerificationStatus
from .state_root import compute_state_root, StateSnapshot, create_state_snapshot, MemoryFileHash

__all__ = [
    "Transition",
    "TransitionStore",
    "create_transition",
    "compute_content_hash",
    "MemoryDAG",
    "CycleDetectedError",
    "MerkleTree",
    "MerkleProof",
    "AnchorBackend",
    "AnchorCapability",
    "AnchorResult",
    "VerifyResult",
    "LocalSignAnchor",
    "OpenTimestampsAnchor",
    "BSVAnchor",
    "get_anchor_backend",
    "VerificationEngine",
    "VerificationStatus",
    "compute_state_root",
    "StateSnapshot",
    "create_state_snapshot",
    "MemoryFileHash",
]
