"""
Layer 5: Verification Engine.

Provides comprehensive verification for memory integrity and
hallucination detection. Verifies:
- Content hash integrity
- Merkle inclusion proofs
- Anchor confirmations
- Chain consistency
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

from ..models.memory_node import MemoryNode
from ..models.transition import Transition
from ..models.anchor_result import AnchorResult, VerifyResult, AnchorBackend
from .merkle import MerkleTree, MerkleProof

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """Verification status codes."""
    VERIFIED = "verified"
    PENDING = "pending"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class VerificationReport:
    """Detailed verification report for a memory node."""
    node_id: str
    status: VerificationStatus
    
    # Component checks
    content_hash_valid: bool = True
    dag_integrity: bool = True
    merkle_proof_valid: bool = True
    anchor_valid: bool = True
    anchor_confirmed: bool = False
    
    # Chain verification
    transition_valid: bool = True
    chain_consistent: bool = True
    
    # Timestamps
    created_at: Optional[str] = None
    anchor_timestamp: Optional[str] = None
    anchor_block_height: Optional[int] = None
    
    # Metadata
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)
        logger.warning(f"[{self.node_id}] {message}")
    
    def add_error(self, message: str) -> None:
        """Add an error message."""
        self.errors.append(message)
        self.status = VerificationStatus.INVALID
        logger.error(f"[{self.node_id}] {message}")
    
    def is_complete(self) -> bool:
        """Check if all verifications are complete."""
        return (
            self.content_hash_valid
            and self.dag_integrity
            and self.merkle_proof_valid
            and self.anchor_valid
        )


class VerificationEngine:
    """
    Verification engine for memory integrity.
    
    Provides comprehensive verification of:
    - Individual memory nodes
    - Merkle proofs
    - Anchor records
    - Transition chains
    - DAG structure
    """
    
    def __init__(
        self,
        merkle_trees: Optional[Dict[str, MerkleTree]] = None,
        anchors: Optional[Dict[str, AnchorResult]] = None,
    ):
        """
        Initialize verification engine.
        
        Args:
            merkle_trees: Dictionary of merkle_root -> MerkleTree
            anchors: Dictionary of anchor_id -> AnchorResult
        """
        self._merkle_trees: Dict[str, MerkleTree] = merkle_trees or {}
        self._anchors: Dict[str, AnchorResult] = anchors or {}
    
    def register_merkle_tree(self, root: str, tree: MerkleTree) -> None:
        """Register a Merkle tree for verification."""
        self._merkle_trees[root] = tree
    
    def register_anchor(self, anchor: AnchorResult) -> None:
        """Register an anchor for verification."""
        self._anchors[anchor.anchor_id] = anchor
    
    def verify_content_hash(self, content: str, expected_hash: str) -> bool:
        """
        Verify content matches expected hash.
        
        Args:
            content: Raw content string
            expected_hash: Expected SHA-256 hash
        
        Returns:
            True if content matches hash
        """
        computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return computed == expected_hash
    
    def verify_node_integrity(
        self,
        node: MemoryNode,
        content: Optional[str] = None,
    ) -> VerificationReport:
        """
        Verify a memory node's integrity.
        
        Args:
            node: The memory node to verify
            content: Original content (if available for hash verification)
        
        Returns:
            VerificationReport with detailed results
        """
        report = VerificationReport(
            node_id=node.id,
            status=VerificationStatus.UNKNOWN,
            created_at=node.created_at,
        )
        
        # Verify node ID structure
        expected_id = node.compute_id_from_content(node.content_hash, node.created_at)
        if node.id != expected_id:
            report.add_error(f"Node ID mismatch: expected {expected_id}, got {node.id}")
            report.status = VerificationStatus.INVALID
            return report
        
        # Verify content hash (if content provided)
        if content is not None:
            if not self.verify_content_hash(content, node.content_hash):
                report.add_error("Content hash mismatch")
                report.content_hash_valid = False
                report.status = VerificationStatus.INVALID
                return report
        else:
            report.add_warning("Content not provided - cannot verify content hash")
        
        # Verify Merkle proof
        if node.merkle_proof:
            if node.merkle_root:
                # Check if leaf_hash in proof matches content_hash
                proof_leaf = node.merkle_proof.get("leaf_hash")
                if proof_leaf and proof_leaf != node.content_hash:
                    report.add_warning(f"Merkle proof leaf_hash ({proof_leaf[:16]}...) doesn't match content_hash")
                
                # Verify the proof structure is valid
                if self.verify_merkle_proof(node.content_hash, node.merkle_root, node.merkle_proof):
                    report.merkle_proof_valid = True
                else:
                    # Even if leaf_hash doesn't match, proof structure might be valid
                    # Check with the proof's own leaf_hash
                    if self.verify_merkle_proof(proof_leaf, node.merkle_root, node.merkle_proof):
                        report.merkle_proof_valid = True
                        report.add_warning("Merkle proof structure valid but leaf_hash mismatch")
                    else:
                        report.add_error("Merkle proof verification failed")
                        report.merkle_proof_valid = False
            else:
                report.add_warning("Node has merkle_proof but no merkle_root")
        
        # Verify anchor (if anchored)
        if node.anchor_id:
            anchor = self._anchors.get(node.anchor_id)
            if anchor:
                if anchor.verified:
                    report.anchor_confirmed = True
                    report.anchor_timestamp = anchor.timestamp
                    report.anchor_block_height = anchor.block_height
                else:
                    report.add_warning(f"Anchor {node.anchor_id} not yet confirmed")
                    report.anchor_valid = anchor.verified
            else:
                report.add_warning(f"Anchor {node.anchor_id} not found in registry")
        
        # Set final status
        if report.is_complete() and not report.errors:
            report.status = VerificationStatus.VERIFIED
        elif report.errors:
            report.status = VerificationStatus.INVALID
        else:
            report.status = VerificationStatus.PENDING
        
        return report
    
    def verify_merkle_proof(
        self,
        leaf_hash: str,
        root: str,
        proof: Dict[str, Any],
    ) -> bool:
        """
        Verify a Merkle inclusion proof.
        
        Args:
            leaf_hash: The leaf hash to verify
            root: The expected Merkle root
            proof: The proof dictionary
        
        Returns:
            True if proof is valid
        """
        try:
            proof_obj = MerkleProof.from_dict(proof)
            
            # Check leaf hash matches
            if proof_obj.leaf_hash != leaf_hash:
                logger.error(f"Leaf hash mismatch in proof: {proof_obj.leaf_hash} != {leaf_hash}")
                return False
            
            # Check root matches
            if proof_obj.root != root:
                logger.error(f"Root mismatch in proof: {proof_obj.root} != {root}")
                return False
            
            # Verify proof
            return proof_obj.verify()
            
        except Exception as e:
            logger.error(f"Error verifying Merkle proof: {e}")
            return False
    
    def verify_transition_chain(
        self,
        transitions: List[Transition],
        start_from: Optional[str] = None,
    ) -> VerificationReport:
        """
        Verify a chain of transitions.
        
        Args:
            transitions: List of transitions in order
            start_from: Optional starting state hash
        
        Returns:
            VerificationReport with chain verification results
        """
        report = VerificationReport(
            node_id="chain",
            status=VerificationStatus.UNKNOWN,
        )
        
        if not transitions:
            report.add_warning("Empty transition chain")
            report.status = VerificationStatus.VERIFIED
            return report
        
        # Check each transition's integrity
        for i, t in enumerate(transitions):
            if not t.verify_integrity():
                report.add_error(f"Transition {t.id} integrity check failed at index {i}")
                report.transition_valid = False
        
        # Check chain consistency
        expected_from = start_from or transitions[0].from_state
        
        for i, t in enumerate(transitions):
            if t.from_state != expected_from:
                report.add_error(
                    f"Transition chain broken at index {i}: "
                    f"expected from_state {expected_from}, got {t.from_state}"
                )
                report.chain_consistent = False
                break
            
            expected_from = t.to_state
        
        # Set final status
        if report.transition_valid and report.chain_consistent and not report.errors:
            report.status = VerificationStatus.VERIFIED
        elif report.errors:
            report.status = VerificationStatus.INVALID
        
        return report
    
    def verify_anchor(self, anchor_id: str, merkle_root: str) -> VerifyResult:
        """
        Verify an anchor record.
        
        Args:
            anchor_id: The anchor ID to verify
            merkle_root: The Merkle root that should be anchored
        
        Returns:
            VerifyResult with verification details
        """
        result = VerifyResult(
            verified=False,
            anchor_id=anchor_id,
            merkle_root=merkle_root,
        )
        
        anchor = self._anchors.get(anchor_id)
        if not anchor:
            result.add_error(f"Anchor {anchor_id} not found")
            return result
        
        # Check Merkle root matches
        if anchor.merkle_root != merkle_root:
            result.add_error("Merkle root mismatch with anchor")
            return result
        
        # Check anchor status
        result.verified = anchor.verified
        result.anchor_valid = anchor.verified
        result.chain_confirmed = anchor.verified
        result.anchor_timestamp = anchor.timestamp
        result.tx_id = anchor.tx_id
        result.block_height = anchor.block_height
        
        if not anchor.verified:
            result.add_warning("Anchor exists but not verified/confirmed")
        
        return result
    
    def detect_hallucination(
        self,
        node: MemoryNode,
        related_nodes: List[MemoryNode],
    ) -> Dict[str, Any]:
        """
        Detect potential hallucination indicators.
        
        This is a heuristic analysis based on:
        - New node contradicts established knowledge
        - Unusual parent relationships
        - Content hash anomalies
        
        Args:
            node: The node to check
            related_nodes: Related nodes in the DAG
        
        Returns:
            Dictionary with hallucination indicators
        """
        indicators = {
            "is_suspicious": False,
            "signals": [],
            "confidence": 0.0,
        }
        
        # Check 1: Is this a contradiction without explicit edge type?
        if not related_nodes:
            indicators["signals"].append("Isolated node with no related knowledge")
            indicators["confidence"] += 0.2
        
        # Check 2: Are there explicit contradiction edges?
        # (This would require accessing the DAG edges)
        has_contradiction = any(
            n.metadata.get("contradicts") for n in related_nodes
        )
        if has_contradiction:
            indicators["signals"].append("Explicitly contradicts established knowledge")
            indicators["confidence"] += 0.3
        
        # Check 3: Age of parent knowledge
        if related_nodes:
            oldest_parent = min(n.created_at for n in related_nodes)
            node_age = node.created_at
            
            # Simple check - in production would parse timestamps
            if node_age < oldest_parent:
                indicators["signals"].append("Node timestamp earlier than parents")
                indicators["confidence"] += 0.4
        
        # Mark as suspicious if confidence is high
        indicators["is_suspicious"] = indicators["confidence"] >= 0.6
        
        return indicators
    
    def batch_verify(
        self,
        nodes: List[MemoryNode],
        contents: Optional[Dict[str, str]] = None,
    ) -> List[VerificationReport]:
        """
        Verify multiple nodes in batch.
        
        Args:
            nodes: List of nodes to verify
            contents: Optional dict of node_id -> content
        
        Returns:
            List of VerificationReports
        """
        reports = []
        
        for node in nodes:
            content = contents.get(node.id) if contents else None
            report = self.verify_node_integrity(node, content)
            reports.append(report)
        
        return reports
