"""
Layer 3: Merkle Tree Construction and Proof Generation.

Implements Merkle tree data structure for efficient batch anchoring
and inclusion proofs. Each leaf is a transition, and the root can be
anchored to a blockchain for timestamping.
"""

import hashlib
import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class MerkleProof:
    """
    A proof that a leaf is included in a Merkle tree.
    
    Contains all necessary information to verify that a specific
    leaf hash is a member of the tree with the given root.
    """
    leaf_hash: str
    root: str
    path: List[str]  # Sibling hashes at each level
    indices: List[int]  # 0 = left, 1 = right at each level
    leaf_index: int  # Position of leaf in the tree
    
    def verify(self) -> bool:
        """
        Verify the proof is correct.
        
        Returns:
            True if the leaf is proven to be in the tree
        """
        current = self.leaf_hash
        
        for i, (sibling, is_right) in enumerate(zip(self.path, self.indices)):
            if is_right:
                current = hashlib.sha256(current.encode() + sibling.encode()).hexdigest()
            else:
                current = hashlib.sha256(sibling.encode() + current.encode()).hexdigest()
        
        return current == self.root
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "leaf_hash": self.leaf_hash,
            "root": self.root,
            "path": self.path,
            "indices": self.indices,
            "leaf_index": self.leaf_index,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MerkleProof":
        """Create from dictionary."""
        return cls(
            leaf_hash=data["leaf_hash"],
            root=data["root"],
            path=data["path"],
            indices=data["indices"],
            leaf_index=data["leaf_index"],
        )


class MerkleTree:
    """
    Merkle Tree implementation for transition batching and anchoring.
    
    Features:
    - Efficient batch construction
    - Inclusion proofs for any leaf
    - Verification without full tree
    - Configurable leaf hashing
    """
    
    def __init__(self, leaves: Optional[List[str]] = None):
        """
        Initialize Merkle tree.
        
        Args:
            leaves: Initial list of leaf hashes
        """
        self.leaves: List[str] = leaves or []
        self.tree: List[List[str]] = []
        self.root: Optional[str] = None
        
        if self.leaves:
            self._build()
    
    def _hash_pair(self, left: str, right: str) -> str:
        """
        Hash two values together.
        
        Order matters: left is concatenated before right.
        """
        return hashlib.sha256(left.encode() + right.encode()).hexdigest()
    
    def _pad_to_power_of_two(self, items: List[str]) -> List[str]:
        """Pad list to power of 2 with repeated last element."""
        n = len(items)
        if n == 0:
            return []
        
        power = 2 ** math.ceil(math.log2(n))
        padded = items.copy()
        
        # If odd number, duplicate last element
        while len(padded) < power:
            if len(padded) % 2 == 1 and padded:
                padded.append(padded[-1])
            else:
                padded.append(padded[-1])
        
        return padded[:power]
    
    def _build(self) -> None:
        """Build the Merkle tree from leaves."""
        if not self.leaves:
            self.root = None
            self.tree = []
            return
        
        # Pad to power of 2
        current_level = self._pad_to_power_of_two(self.leaves)
        self.tree = [current_level]
        
        # Build levels up to root
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self._hash_pair(left, right))
            
            self.tree.append(next_level)
            current_level = next_level
        
        self.root = current_level[0] if current_level else None
    
    def add_leaf(self, leaf_hash: str) -> None:
        """
        Add a new leaf to the tree.
        
        Note: This rebuilds the entire tree. For efficient batch adds,
        use add_leaves() instead.
        """
        self.leaves.append(leaf_hash)
        self._build()
    
    def add_leaves(self, leaf_hashes: List[str]) -> None:
        """
        Add multiple leaves efficiently.
        
        Appends to internal list and rebuilds.
        """
        self.leaves.extend(leaf_hashes)
        self._build()
    
    def get_proof(self, leaf_hash: str) -> Optional[MerkleProof]:
        """
        Generate a Merkle proof for a leaf.
        
        Args:
            leaf_hash: The leaf hash to prove
        
        Returns:
            MerkleProof if found, None otherwise
        """
        if not self.root or leaf_hash not in self.leaves:
            return None
        
        leaf_index = self.leaves.index(leaf_hash)
        
        # Start from the original (unpadded) leaf position
        path = []
        indices = []
        current_index = leaf_index
        
        # Process each level except root
        for level in range(len(self.tree) - 1):
            level_nodes = self.tree[level]
            
            # Determine sibling position
            if current_index % 2 == 0:
                # Left child, sibling is right
                sibling_index = current_index + 1
                is_right = True
            else:
                # Right child, sibling is left
                sibling_index = current_index - 1
                is_right = False
            
            # Handle case where sibling is out of bounds (padded node)
            if sibling_index >= len(level_nodes):
                # Use self as sibling for padded node
                sibling_index = current_index
                is_right = False
            
            sibling = level_nodes[sibling_index]
            path.append(sibling)
            indices.append(1 if is_right else 0)
            
            # Move to parent
            current_index = current_index // 2
        
        return MerkleProof(
            leaf_hash=leaf_hash,
            root=self.root,
            path=path,
            indices=indices,
            leaf_index=leaf_index,
        )
    
    def verify_proof(self, proof: MerkleProof) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            proof: The proof to verify
        
        Returns:
            True if proof is valid
        """
        return proof.verify()
    
    def get_proof_for_index(self, index: int) -> Optional[MerkleProof]:
        """
        Get proof for a leaf by index.
        
        Args:
            index: Leaf index
        
        Returns:
            MerkleProof if index is valid, None otherwise
        """
        if index < 0 or index >= len(self.leaves):
            return None
        
        return self.get_proof(self.leaves[index])
    
    @staticmethod
    def compute_root_from_leaves(leaves: List[str]) -> Optional[str]:
        """
        Compute Merkle root from a list of leaves without storing the tree.
        
        Useful for verification without full tree.
        """
        if not leaves:
            return None
        
        current = MerkleTree._pad_to_power_of_two_static(leaves)
        
        while len(current) > 1:
            next_level = []
            
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(hashlib.sha256(left.encode() + right.encode()).hexdigest())
            
            current = next_level
        
        return current[0] if current else None
    
    @staticmethod
    def _pad_to_power_of_two_static(items: List[str]) -> List[str]:
        """Static version of padding."""
        n = len(items)
        if n == 0:
            return []
        
        power = 2 ** math.ceil(math.log2(n))
        padded = items.copy()
        
        while len(padded) < power:
            if len(padded) % 2 == 1 and padded:
                padded.append(padded[-1])
            else:
                padded.append(padded[-1])
        
        return padded[:power]
    
    @staticmethod
    def verify_inclusion(leaf_hash: str, proof: Dict[str, Any]) -> bool:
        """
        Verify a leaf is included in a root using proof data.
        
        Args:
            leaf_hash: The leaf to verify
            proof: Proof dict with root, path, indices
        
        Returns:
            True if leaf is in the tree
        """
        proof_obj = MerkleProof.from_dict(proof)
        if proof_obj.leaf_hash != leaf_hash:
            return False
        return proof_obj.verify()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize tree structure."""
        return {
            "leaves": self.leaves,
            "tree": self.tree,
            "root": self.root,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MerkleTree":
        """Deserialize tree."""
        tree = cls(leaves=data.get("leaves", []))
        tree.tree = data.get("tree", [])
        tree.root = data.get("root")
        return tree
    
    def __len__(self) -> int:
        """Get number of leaves."""
        return len(self.leaves)
    
    def __bool__(self) -> bool:
        """Check if tree has leaves."""
        return len(self.leaves) > 0


def create_merkle_tree_from_transitions(transitions: List[Any]) -> MerkleTree:
    """
    Create a Merkle tree from a list of transitions.
    
    Each transition is serialized and hashed to form leaves.
    
    Args:
        transitions: List of Transition objects
    
    Returns:
        MerkleTree with transition hashes as leaves
    """
    import json
    
    leaves = []
    for t in transitions:
        # Use the transition's JSON serialization
        leaf_data = t.to_json_bytes()
        leaf_hash = hashlib.sha256(leaf_data).hexdigest()
        leaves.append(leaf_hash)
    
    return MerkleTree(leaves=leaves)


def compute_merkle_proof_batch(
    transitions: List[Any],
    indices: List[int]
) -> List[MerkleProof]:
    """
    Compute Merkle proofs for multiple transitions.
    
    More efficient than computing proofs one by one.
    
    Args:
        transitions: List of Transition objects
        indices: Indices of transitions to prove
    
    Returns:
        List of MerkleProof objects
    """
    tree = create_merkle_tree_from_transitions(transitions)
    proofs = []
    
    for idx in indices:
        proof = tree.get_proof_for_index(idx)
        if proof:
            proofs.append(proof)
    
    return proofs
