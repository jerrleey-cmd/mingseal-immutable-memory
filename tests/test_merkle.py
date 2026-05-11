"""
Unit tests for the Merkle tree implementation.
"""

import pytest
from mingseal_immutable_memory.core.merkle import (
    MerkleTree,
    MerkleProof,
    create_merkle_tree_from_transitions,
)
from mingseal_immutable_memory.core.transition import create_transition


class TestMerkleTree:
    """Tests for the MerkleTree class."""
    
    def test_empty_tree(self):
        """Test empty tree."""
        tree = MerkleTree()
        
        assert tree.root is None
        assert len(tree) == 0
    
    def test_single_leaf(self):
        """Test tree with single leaf."""
        tree = MerkleTree(leaves=["a"])
        
        assert tree.root is not None
        assert len(tree) == 1
    
    def test_power_of_two_leaves(self):
        """Test tree with power of 2 leaves."""
        leaves = ["a", "b", "c", "d"]
        tree = MerkleTree(leaves=leaves)
        
        assert tree.root is not None
        assert len(tree) == 4
    
    def test_non_power_of_two_leaves(self):
        """Test tree with non-power of 2 leaves (padding)."""
        leaves = ["a", "b", "c"]
        tree = MerkleTree(leaves=leaves)
        
        assert tree.root is not None
        assert len(tree) == 3
    
    def test_deterministic_root(self):
        """Test that same leaves produce same root."""
        leaves = ["a", "b", "c", "d"]
        
        tree1 = MerkleTree(leaves=leaves)
        tree2 = MerkleTree(leaves=leaves)
        
        assert tree1.root == tree2.root
    
    def test_different_leaves_different_root(self):
        """Test that different leaves produce different root."""
        tree1 = MerkleTree(leaves=["a", "b"])
        tree2 = MerkleTree(leaves=["a", "c"])
        
        assert tree1.root != tree2.root
    
    def test_add_leaf(self):
        """Test adding a leaf."""
        tree = MerkleTree(leaves=["a", "b"])
        original_root = tree.root
        
        tree.add_leaf("c")
        
        assert len(tree) == 3
        assert tree.root != original_root
    
    def test_add_leaves(self):
        """Test adding multiple leaves."""
        tree = MerkleTree(leaves=["a"])
        
        tree.add_leaves(["b", "c", "d"])
        
        assert len(tree) == 4


class TestMerkleProof:
    """Tests for Merkle proofs."""
    
    def test_proof_generation(self):
        """Test generating a proof for a leaf."""
        leaves = ["a", "b", "c", "d"]
        tree = MerkleTree(leaves=leaves)
        
        proof = tree.get_proof("a")
        
        assert proof is not None
        assert proof.leaf_hash == "a"
        assert proof.root == tree.root
        assert len(proof.path) > 0
    
    def test_proof_verification(self):
        """Test verifying a proof."""
        leaves = ["a", "b", "c", "d"]
        tree = MerkleTree(leaves=leaves)
        
        proof = tree.get_proof("c")
        
        assert proof.verify() is True
    
    def test_proof_verification_fails_wrong_leaf(self):
        """Test that proof verification fails with wrong leaf."""
        leaves = ["a", "b", "c", "d"]
        tree = MerkleTree(leaves=leaves)
        
        proof = tree.get_proof("a")
        
        # Change the proof's leaf hash
        proof.leaf_hash = "z"
        
        assert proof.verify() is False
    
    def test_proof_serialization(self):
        """Test proof serialization."""
        tree = MerkleTree(leaves=["a", "b", "c", "d"])
        proof = tree.get_proof("b")
        
        proof_dict = proof.to_dict()
        restored = MerkleProof.from_dict(proof_dict)
        
        assert restored.leaf_hash == proof.leaf_hash
        assert restored.root == proof.root
        assert restored.verify() is True
    
    def test_proof_for_index(self):
        """Test getting proof by index."""
        leaves = ["a", "b", "c", "d"]
        tree = MerkleTree(leaves=leaves)
        
        proof = tree.get_proof_for_index(2)
        
        assert proof is not None
        assert proof.leaf_hash == "c"


class TestStaticMethods:
    """Tests for static Merkle tree methods."""
    
    def test_compute_root_from_leaves(self):
        """Test static root computation."""
        leaves = ["a", "b", "c", "d"]
        
        root = MerkleTree.compute_root_from_leaves(leaves)
        
        assert root is not None
        assert len(root) == 64  # SHA-256 hex
    
    def test_compute_root_empty(self):
        """Test static root computation with empty leaves."""
        root = MerkleTree.compute_root_from_leaves([])
        
        assert root is None
    
    def test_verify_inclusion(self):
        """Test static inclusion verification."""
        tree = MerkleTree(leaves=["a", "b", "c", "d"])
        proof = tree.get_proof("b")
        
        result = MerkleTree.verify_inclusion("b", proof.to_dict())
        
        assert result is True


class TestCreateFromTransitions:
    """Tests for creating Merkle tree from transitions."""
    
    def test_create_from_transitions(self):
        """Test creating Merkle tree from transition objects."""
        t1 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi!",
        )
        
        t2 = create_transition(
            from_state=t1.to_state,
            input_type="user_msg",
            input_content="How are you?",
            output_type="reply",
            output_content="I'm good!",
        )
        
        tree = create_merkle_tree_from_transitions([t1, t2])
        
        assert tree.root is not None
        assert len(tree) == 2
    
    def test_proofs_for_transitions(self):
        """Test getting proofs for transitions."""
        t1 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="A",
            output_type="reply",
            output_content="B",
        )
        
        t2 = create_transition(
            from_state=t1.to_state,
            input_type="user_msg",
            input_content="C",
            output_type="reply",
            output_content="D",
        )
        
        tree = create_merkle_tree_from_transitions([t1, t2])
        
        # Get proofs
        proof1 = tree.get_proof(t1.compute_id())
        proof2 = tree.get_proof(t2.compute_id())
        
        assert proof1 is not None
        assert proof2 is not None
        assert proof1.verify() is True
        assert proof2.verify() is True
