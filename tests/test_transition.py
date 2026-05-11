"""
Unit tests for the Transition model and TransitionStore.
"""

import pytest
from mingseal_immutable_memory.core.transition import (
    Transition,
    TransitionStore,
    create_transition,
    compute_content_hash,
)
from mingseal_immutable_memory.models.transition import compute_state_hash


class TestTransition:
    """Tests for the Transition model."""
    
    def test_create_transition_basic(self):
        """Test basic transition creation."""
        t = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi there!",
        )
        
        assert t.from_state == "genesis"
        assert t.input_type == "user_msg"
        assert t.output_type == "reply"
        assert t.id is not None
        assert len(t.id) == 64  # SHA-256 hex length
    
    def test_transition_idempotent(self):
        """Test that creating same transition produces same ID."""
        t1 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi there!",
        )
        
        t2 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi there!",
        )
        
        assert t1.id == t2.id
    
    def test_different_content_different_hash(self):
        """Test that different content produces different hashes."""
        t1 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi!",
        )
        
        t2 = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Goodbye",
            output_type="reply",
            output_content="Bye!",
        )
        
        assert t1.id != t2.id
        assert t1.input_hash != t2.input_hash
    
    def test_verify_integrity(self):
        """Test transition integrity verification."""
        t = create_transition(
            from_state="genesis",
            input_type="tool_call",
            input_content='{"tool": "search"}',
            output_type="tool_result",
            output_content='{"results": []}',
        )
        
        assert t.verify_integrity() is True
    
    def test_to_json_bytes(self):
        """Test JSON serialization."""
        t = create_transition(
            from_state="genesis",
            input_type="user_msg",
            input_content="Test",
            output_type="reply",
            output_content="Result",
        )
        
        json_bytes = t.to_json_bytes()
        assert isinstance(json_bytes, bytes)
        assert b"from_state" in json_bytes


class TestTransitionStore:
    """Tests for the TransitionStore."""
    
    def test_initialization(self):
        """Test store initialization."""
        store = TransitionStore()
        
        assert store.latest_state == TransitionStore.GENESIS_HASH
        assert len(store.state_chain) == 1
        assert store.count() == 0
    
    def test_capture_single_transition(self):
        """Test capturing a single transition."""
        store = TransitionStore()
        
        t = store.capture(
            input_type="user_msg",
            input_content="Hello",
            output_type="reply",
            output_content="Hi!",
        )
        
        assert store.count() == 1
        assert store.latest_state == t.to_state
        assert len(store.state_chain) == 2
    
    def test_capture_chain(self):
        """Test capturing multiple transitions."""
        store = TransitionStore()
        
        t1 = store.capture(
            input_type="user_msg",
            input_content="First",
            output_type="reply",
            output_content="Response 1",
        )
        
        t2 = store.capture(
            input_type="user_msg",
            input_content="Second",
            output_type="reply",
            output_content="Response 2",
        )
        
        assert store.count() == 2
        assert t2.from_state == t1.to_state
        assert store.latest_state == t2.to_state
    
    def test_get_transition(self):
        """Test retrieving a transition."""
        store = TransitionStore()
        
        t = store.capture(
            input_type="user_msg",
            input_content="Test",
            output_type="reply",
            output_content="Result",
        )
        
        retrieved = store.get(t.id)
        assert retrieved is not None
        assert retrieved.id == t.id
    
    def test_get_latest(self):
        """Test getting latest transitions."""
        store = TransitionStore()
        
        for i in range(15):
            store.capture(
                input_type="user_msg",
                input_content=f"Message {i}",
                output_type="reply",
                output_content=f"Response {i}",
            )
        
        latest = store.get_latest(5)
        assert len(latest) == 5
    
    def test_verify_chain_integrity(self):
        """Test chain integrity verification."""
        store = TransitionStore()
        
        for i in range(5):
            store.capture(
                input_type="user_msg",
                input_content=f"Message {i}",
                output_type="reply",
                output_content=f"Response {i}",
            )
        
        assert store.verify_chain_integrity() is True
    
    def test_serialization(self):
        """Test store serialization and deserialization."""
        store = TransitionStore()
        
        store.capture(
            input_type="user_msg",
            input_content="Test",
            output_type="reply",
            output_content="Result",
        )
        
        # Serialize
        data = store.serialize()
        
        # Deserialize
        restored = TransitionStore.from_serialized(data)
        
        assert restored.count() == store.count()
        assert restored.latest_state == store.latest_state


class TestHelperFunctions:
    """Tests for helper functions."""
    
    def test_compute_content_hash(self):
        """Test content hash computation."""
        hash1 = compute_content_hash("Hello")
        hash2 = compute_content_hash("Hello")
        hash3 = compute_content_hash("World")
        
        assert hash1 == hash2
        assert hash1 != hash3
        assert len(hash1) == 64  # SHA-256 hex length
    
    def test_compute_state_hash(self):
        """Test state hash computation."""
        hash1 = compute_state_hash("a", "b")
        hash2 = compute_state_hash("a", "b")
        hash3 = compute_state_hash("a", "c")
        
        assert hash1 == hash2
        assert hash1 != hash3
    
    def test_state_hash_deterministic_order(self):
        """Test that state hash is order-independent."""
        hash1 = compute_state_hash("a", "b")
        hash2 = compute_state_hash("b", "a")
        
        assert hash1 == hash2
