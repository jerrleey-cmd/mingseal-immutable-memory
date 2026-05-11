"""
Unit tests for state root computation.
"""

import pytest
from mingseal_immutable_memory.core.state_root import (
    compute_state_root,
    compute_state_root_from_contents,
    create_state_snapshot,
    verify_state_snapshot,
    compute_delta,
    StateSnapshot,
    MemoryFileHash,
)
from mingseal_immutable_memory.core.merkle import MerkleTree


class TestComputeStateRoot:
    """Tests for state root computation."""
    
    def test_compute_from_hashes(self):
        """Test computing state root from hash dict."""
        memory_hashes = {
            "soul": "abc123",
            "user": "def456",
            "memory": "ghi789",
        }
        
        root = compute_state_root(memory_hashes)
        
        assert root is not None
        assert len(root) == 64  # SHA-256 hex
    
    def test_empty_hashes(self):
        """Test computing state root from empty dict."""
        root = compute_state_root({})
        
        assert root is not None
    
    def test_single_hash(self):
        """Test computing state root from single hash."""
        root = compute_state_root({"only": "hash123"})
        
        assert root is not None
    
    def test_deterministic_order(self):
        """Test that order doesn't affect result."""
        hashes1 = {"a": "1", "b": "2", "c": "3"}
        hashes2 = {"c": "3", "a": "1", "b": "2"}
        
        root1 = compute_state_root(hashes1)
        root2 = compute_state_root(hashes2)
        
        assert root1 == root2
    
    def test_different_hashes_different_root(self):
        """Test that different hashes produce different roots."""
        hashes1 = {"a": "1", "b": "2"}
        hashes2 = {"a": "1", "b": "3"}
        
        root1 = compute_state_root(hashes1)
        root2 = compute_state_root(hashes2)
        
        assert root1 != root2


class TestComputeStateRootFromContents:
    """Tests for computing state root from contents."""
    
    def test_compute_from_contents(self):
        """Test computing state root from content dict."""
        contents = {
            "soul": "This is my soul file content",
            "user": "User preferences and history",
            "memory": "Important memories and facts",
        }
        
        root, file_hashes = compute_state_root_from_contents(contents)
        
        assert root is not None
        assert len(file_hashes) == 3
        
        # Check file hashes
        names = {fh.name for fh in file_hashes}
        assert names == {"soul", "user", "memory"}
        
        for fh in file_hashes:
            assert fh.content_hash is not None
            assert fh.size > 0
    
    def test_empty_contents(self):
        """Test computing from empty contents."""
        root, file_hashes = compute_state_root_from_contents({})
        
        assert root is not None
        assert len(file_hashes) == 0


class TestStateSnapshot:
    """Tests for StateSnapshot model."""
    
    def test_create_snapshot(self):
        """Test creating a state snapshot."""
        memory_hashes = {
            "soul": "abc123",
            "user": "def456",
        }
        
        snapshot = create_state_snapshot(memory_hashes)
        
        assert snapshot.snapshot_id.startswith("snap_")
        assert snapshot.state_root is not None
        assert len(snapshot.memory_files) == 2
        assert snapshot.timestamp is not None
    
    def test_snapshot_serialization(self):
        """Test snapshot serialization."""
        memory_hashes = {"test": "hash"}
        snapshot = create_state_snapshot(memory_hashes)
        
        data = snapshot.to_dict()
        restored = StateSnapshot.from_dict(data)
        
        assert restored.snapshot_id == snapshot.snapshot_id
        assert restored.state_root == snapshot.state_root
        assert len(restored.memory_files) == len(snapshot.memory_files)
    
    def test_snapshot_with_previous(self):
        """Test snapshot with previous reference."""
        snapshot1 = create_state_snapshot({"a": "1"})
        snapshot2 = create_state_snapshot(
            {"a": "1", "b": "2"},
            previous_snapshot_id=snapshot1.snapshot_id,
        )
        
        assert snapshot2.previous_snapshot_id == snapshot1.snapshot_id


class TestVerifyStateSnapshot:
    """Tests for state snapshot verification."""
    
    def test_verify_valid_snapshot(self):
        """Test verifying a valid snapshot."""
        import hashlib
        contents = {
            "soul": "Soul content",
            "user": "User content",
        }
        
        # Compute correct hashes using SHA-256
        content_hashes = {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in contents.items()
        }
        
        snapshot = create_state_snapshot(content_hashes)
        
        result = verify_state_snapshot(snapshot, content_hashes)
        
        assert result is True
    
    def test_verify_invalid_snapshot(self):
        """Test verifying a snapshot with wrong hashes."""
        snapshot = create_state_snapshot({"test": "correct_hash"})
        
        wrong_hashes = {"test": "wrong_hash"}
        
        result = verify_state_snapshot(snapshot, wrong_hashes)
        
        assert result is False


class TestComputeDelta:
    """Tests for delta computation."""
    
    def test_delta_added(self):
        """Test delta with added files."""
        old = create_state_snapshot({"a": "1"})
        new = create_state_snapshot({"a": "1", "b": "2"})
        
        delta = compute_delta(old, new)
        
        assert "a" in delta["unchanged_files"]
        assert "b" in delta["added_files"]
        assert delta["total_changes"] == 1
    
    def test_delta_removed(self):
        """Test delta with removed files."""
        old = create_state_snapshot({"a": "1", "b": "2"})
        new = create_state_snapshot({"a": "1"})
        
        delta = compute_delta(old, new)
        
        assert "a" in delta["unchanged_files"]
        assert "b" in delta["removed_files"]
    
    def test_delta_modified(self):
        """Test delta with modified files."""
        old = create_state_snapshot({"a": "1"})
        new = create_state_snapshot({"a": "2"})
        
        delta = compute_delta(old, new)
        
        assert "a" in delta["modified_files"]
        assert delta["total_changes"] == 1
    
    def test_delta_no_changes(self):
        """Test delta with no changes."""
        snapshot = create_state_snapshot({"a": "1"})
        
        delta = compute_delta(snapshot, snapshot)
        
        assert delta["total_changes"] == 0
        assert "a" in delta["unchanged_files"]
