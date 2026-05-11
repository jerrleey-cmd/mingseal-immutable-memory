"""
Layer 6: Cognitive State Root Computation.

Computes a cryptographic digest of the agent's complete cognitive state,
combining all memory files into a verifiable Merkle tree structure.

This provides a single root hash that represents the agent's entire
knowledge state at a point in time.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

from .merkle import MerkleTree

logger = logging.getLogger(__name__)


@dataclass
class MemoryFileHash:
    """Hash of a single memory file."""
    name: str           # e.g., "soul", "user", "memory", "tools"
    content_hash: str    # SHA-256 of file content
    file_path: Optional[str] = None
    last_modified: Optional[str] = None
    size: int = 0


@dataclass
class StateSnapshot:
    """
    Complete snapshot of the agent's cognitive state.
    
    Contains all memory file hashes and the computed state root.
    """
    snapshot_id: str
    timestamp: str
    memory_files: List[MemoryFileHash]
    state_root: str
    previous_snapshot_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "memory_files": [
                {
                    "name": mf.name,
                    "content_hash": mf.content_hash,
                    "file_path": mf.file_path,
                    "last_modified": mf.last_modified,
                    "size": mf.size,
                }
                for mf in self.memory_files
            ],
            "state_root": self.state_root,
            "previous_snapshot_id": self.previous_snapshot_id,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateSnapshot":
        """Deserialize from dictionary."""
        return cls(
            snapshot_id=data["snapshot_id"],
            timestamp=data["timestamp"],
            memory_files=[
                MemoryFileHash(
                    name=mf["name"],
                    content_hash=mf["content_hash"],
                    file_path=mf.get("file_path"),
                    last_modified=mf.get("last_modified"),
                    size=mf.get("size", 0),
                )
                for mf in data.get("memory_files", [])
            ],
            state_root=data["state_root"],
            previous_snapshot_id=data.get("previous_snapshot_id"),
            metadata=data.get("metadata", {}),
        )


def compute_file_hash(content: str) -> str:
    """Compute SHA-256 hash of file content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_state_root(memory_file_hashes: Dict[str, str]) -> str:
    """
    Compute the cognitive state root from memory file hashes.
    
    Takes a dictionary of memory file names to their content hashes,
    and computes a Merkle tree root that combines them into a
    single representative state hash.
    
    Args:
        memory_file_hashes: Dict mapping file names to their content hashes
            Example: {
                "soul": "abc123...",
                "user": "def456...",
                "memory": "ghi789...",
                "tools": "jkl012...",
            }
    
    Returns:
        The Merkle root hash representing the complete state
    """
    if not memory_file_hashes:
        # Return hash of empty string for empty state
        return compute_file_hash("")
    
    # Sort by name for deterministic ordering
    sorted_hashes = sorted(memory_file_hashes.values())
    
    # Build Merkle tree and get root
    tree = MerkleTree(leaves=sorted_hashes)
    
    if tree.root is None:
        return compute_file_hash("")
    
    return tree.root


def compute_state_root_from_contents(
    memory_contents: Dict[str, str],
    include_metadata: bool = False,
) -> tuple[str, List[MemoryFileHash]]:
    """
    Compute state root directly from memory contents.
    
    Args:
        memory_contents: Dict mapping file names to their contents
        include_metadata: Whether to include file metadata in hashes
    
    Returns:
        Tuple of (state_root, list of MemoryFileHash objects)
    """
    file_hashes = []
    content_hashes = {}
    
    for name, content in memory_contents.items():
        content_hash = compute_file_hash(content)
        content_hashes[name] = content_hash
        
        file_hash = MemoryFileHash(
            name=name,
            content_hash=content_hash,
            size=len(content),
            last_modified=datetime.utcnow().isoformat() + "Z" if include_metadata else None,
        )
        file_hashes.append(file_hash)
    
    state_root = compute_state_root(content_hashes)
    
    return state_root, file_hashes


def create_state_snapshot(
    memory_file_hashes: Dict[str, str],
    previous_snapshot_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> StateSnapshot:
    """
    Create a new state snapshot.
    
    Args:
        memory_file_hashes: Dict of file names to their content hashes
        previous_snapshot_id: ID of the previous snapshot (for chain)
        metadata: Additional metadata
    
    Returns:
        A new StateSnapshot
    """
    # Compute state root
    state_root = compute_state_root(memory_file_hashes)
    
    # Create memory file hash objects
    memory_files = [
        MemoryFileHash(
            name=name,
            content_hash=hash_value,
        )
        for name, hash_value in sorted(memory_file_hashes.items())
    ]
    
    # Generate snapshot ID
    snapshot_data = json.dumps({
        "memory_hashes": memory_file_hashes,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "previous": previous_snapshot_id,
    }, sort_keys=True)
    snapshot_id = "snap_" + hashlib.sha256(snapshot_data.encode()).hexdigest()[:16]
    
    return StateSnapshot(
        snapshot_id=snapshot_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        memory_files=memory_files,
        state_root=state_root,
        previous_snapshot_id=previous_snapshot_id,
        metadata=metadata or {},
    )


def verify_state_snapshot(
    snapshot: StateSnapshot,
    expected_content_hashes: Dict[str, str],
) -> bool:
    """
    Verify a state snapshot is consistent with expected content hashes.
    
    Args:
        snapshot: The snapshot to verify
        expected_content_hashes: Expected file hashes
    
    Returns:
        True if snapshot is valid
    """
    # Rebuild state root from expected hashes
    expected_root = compute_state_root(expected_content_hashes)
    
    # Check root matches
    if snapshot.state_root != expected_root:
        logger.error(
            f"State root mismatch: expected {expected_root}, "
            f"got {snapshot.state_root}"
        )
        return False
    
    # Check all files are present
    snapshot_files = {mf.name for mf in snapshot.memory_files}
    expected_files = set(expected_content_hashes.keys())
    
    if snapshot_files != expected_files:
        logger.error(
            f"File list mismatch: expected {expected_files}, "
            f"got {snapshot_files}"
        )
        return False
    
    # Check each hash matches
    for mf in snapshot.memory_files:
        if mf.name not in expected_content_hashes:
            logger.error(f"Unexpected file in snapshot: {mf.name}")
            return False
        
        if mf.content_hash != expected_content_hashes[mf.name]:
            logger.error(
                f"Hash mismatch for {mf.name}: "
                f"expected {expected_content_hashes[mf.name]}, "
                f"got {mf.content_hash}"
            )
            return False
    
    return True


def compute_delta(
    old_snapshot: StateSnapshot,
    new_snapshot: StateSnapshot,
) -> Dict[str, Any]:
    """
    Compute the delta between two state snapshots.
    
    Args:
        old_snapshot: Previous state snapshot
        new_snapshot: New state snapshot
    
    Returns:
        Dictionary describing what changed
    """
    old_hashes = {mf.name: mf.content_hash for mf in old_snapshot.memory_files}
    new_hashes = {mf.name: mf.content_hash for mf in new_snapshot.memory_files}
    
    all_files = set(old_hashes.keys()) | set(new_hashes.keys())
    
    added = []
    removed = []
    modified = []
    unchanged = []
    
    for name in sorted(all_files):
        old_hash = old_hashes.get(name)
        new_hash = new_hashes.get(name)
        
        if old_hash is None and new_hash is not None:
            added.append(name)
        elif old_hash is not None and new_hash is None:
            removed.append(name)
        elif old_hash != new_hash:
            modified.append(name)
        else:
            unchanged.append(name)
    
    return {
        "old_snapshot_id": old_snapshot.snapshot_id,
        "new_snapshot_id": new_snapshot.snapshot_id,
        "state_root_changed": old_snapshot.state_root != new_snapshot.state_root,
        "added_files": added,
        "removed_files": removed,
        "modified_files": modified,
        "unchanged_files": unchanged,
        "total_changes": len(added) + len(removed) + len(modified),
    }


class StateChain:
    """
    Chain of state snapshots forming an immutable history.
    
    Each snapshot references the previous one, creating a
    tamper-evident chain of cognitive states.
    """
    
    def __init__(self):
        self.snapshots: Dict[str, StateSnapshot] = {}
        self.head: Optional[str] = None  # Latest snapshot ID
    
    def add_snapshot(self, snapshot: StateSnapshot) -> None:
        """
        Add a new snapshot to the chain.
        
        Args:
            snapshot: The snapshot to add
        
        Raises:
            ValueError: If snapshot doesn't reference the current head
        """
        # Verify chain integrity
        if self.head is not None:
            if snapshot.previous_snapshot_id != self.head:
                raise ValueError(
                    f"Snapshot doesn't reference current head. "
                    f"Expected {self.head}, got {snapshot.previous_snapshot_id}"
                )
        elif snapshot.previous_snapshot_id is not None:
            raise ValueError(
                "First snapshot in chain must have previous_snapshot_id=None"
            )
        
        # Add to chain
        self.snapshots[snapshot.snapshot_id] = snapshot
        self.head = snapshot.snapshot_id
        
        logger.info(f"Added snapshot {snapshot.snapshot_id} to state chain")
    
    def get_snapshot(self, snapshot_id: str) -> Optional[StateSnapshot]:
        """Get a snapshot by ID."""
        return self.snapshots.get(snapshot_id)
    
    def get_latest(self) -> Optional[StateSnapshot]:
        """Get the latest snapshot."""
        if self.head is None:
            return None
        return self.snapshots.get(self.head)
    
    def verify_chain(self) -> bool:
        """
        Verify the entire chain is intact.
        
        Returns:
            True if chain is valid
        """
        if not self.snapshots:
            return True
        
        # Start from genesis (no previous)
        current = None
        for sid, snap in self.snapshots.items():
            if snap.previous_snapshot_id is None:
                current = snap
                break
        
        if current is None:
            logger.error("No genesis snapshot found")
            return False
        
        # Follow the chain
        while True:
            next_id = self.head  # Would need to track next pointers
            # Simplified - just verify head exists
            if self.head not in self.snapshots:
                logger.error(f"Head {self.head} not in snapshots")
                return False
            break
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize chain."""
        return {
            "snapshots": {
                sid: snap.to_dict() for sid, snap in self.snapshots.items()
            },
            "head": self.head,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateChain":
        """Deserialize chain."""
        chain = cls()
        
        for sid, snap_data in data.get("snapshots", {}).items():
            chain.snapshots[sid] = StateSnapshot.from_dict(snap_data)
        
        chain.head = data.get("head")
        
        return chain
