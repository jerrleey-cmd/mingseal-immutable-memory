"""
Layer 1: State Transition Capture and Recording.

This module handles capturing and recording cognitive state transitions
in an AI agent's reasoning process. Each transition represents a single
step from one cognitive state to another.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from ..models.transition import Transition, create_transition, compute_content_hash

logger = logging.getLogger(__name__)


@dataclass
class TransitionStore:
    """
    Stores and manages cognitive state transitions.
    
    This is the primary interface for recording agent cognition steps.
    Each transition captures a state change based on input/output pairs.
    """
    transitions: Dict[str, Transition] = field(default_factory=dict)
    state_chain: List[str] = field(default_factory=list)  # List of state hashes
    latest_state: str = "genesis"  # Initial state hash
    
    # Genesis state hash (empty state)
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    
    def __post_init__(self):
        """Initialize with genesis state if empty."""
        if not self.state_chain:
            self.state_chain = [self.GENESIS_HASH]
            self.latest_state = self.GENESIS_HASH
    
    def capture(
        self,
        input_type: str,
        input_content: str,
        output_type: str,
        output_content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Transition:
        """
        Capture a new cognitive state transition.
        
        This is the main entry point for recording agent cognition.
        It automatically computes the new state and creates the transition.
        
        Args:
            input_type: Type of input (user_msg, tool_call, timer, memory_update)
            input_content: The actual input content
            output_type: Type of output (reply, tool_result, memory_write)
            output_content: The actual output content
            metadata: Optional additional metadata
        
        Returns:
            The created Transition
        """
        # Create transition from current state
        transition = create_transition(
            from_state=self.latest_state,
            input_type=input_type,
            input_content=input_content,
            output_type=output_type,
            output_content=output_content,
            metadata=metadata,
        )
        
        # Store and update state
        self.transitions[transition.id] = transition
        self.state_chain.append(transition.to_state)
        self.latest_state = transition.to_state
        
        logger.info(
            f"Captured transition {transition.id[:8]}... "
            f"({input_type} -> {output_type})"
        )
        
        return transition
    
    def get(self, transition_id: str) -> Optional[Transition]:
        """Get a transition by ID."""
        return self.transitions.get(transition_id)
    
    def get_by_state(self, state_hash: str) -> Optional[Transition]:
        """Get the transition that led to a specific state."""
        for transition in self.transitions.values():
            if transition.to_state == state_hash:
                return transition
        return None
    
    def get_chain(self, start_state: Optional[str] = None, limit: int = 100) -> List[Transition]:
        """
        Get the transition chain starting from a state.
        
        Args:
            start_state: Starting state hash (defaults to genesis)
            limit: Maximum number of transitions to return
        
        Returns:
            List of transitions in chronological order
        """
        if start_state is None:
            start_state = self.GENESIS_HASH
        
        # Find starting index
        start_idx = 0
        for i, state in enumerate(self.state_chain):
            if state == start_state:
                start_idx = i
                break
        else:
            logger.warning(f"State {start_state} not found in chain")
            return []
        
        # Get transitions that led to states from start_idx
        result = []
        for i in range(start_idx, min(start_idx + limit, len(self.state_chain))):
            state = self.state_chain[i]
            transition = self.get_by_state(state)
            if transition:
                result.append(transition)
        
        return result
    
    def get_latest(self, n: int = 10) -> List[Transition]:
        """Get the N most recent transitions."""
        ids = list(self.transitions.keys())
        ids.sort()
        recent_ids = ids[-n:] if len(ids) > n else ids
        return [self.transitions[tid] for tid in recent_ids]
    
    def count(self) -> int:
        """Get total number of transitions."""
        return len(self.transitions)
    
    def get_state_at(self, index: int) -> Optional[str]:
        """Get the state hash at a specific index in the chain."""
        if 0 <= index < len(self.state_chain):
            return self.state_chain[index]
        return None
    
    def verify_chain_integrity(self) -> bool:
        """
        Verify the integrity of the entire transition chain.
        
        Returns:
            True if all transitions are valid and chain is consistent
        """
        if len(self.state_chain) == 0:
            return True
        
        # Check genesis
        if self.state_chain[0] != self.GENESIS_HASH:
            logger.error("Chain does not start with genesis hash")
            return False
        
        # Check each transition's from_state matches previous to_state
        for i in range(1, len(self.state_chain)):
            state = self.state_chain[i]
            transition = self.get_by_state(state)
            
            if transition is None:
                logger.error(f"State {state} has no corresponding transition")
                return False
            
            expected_from = self.state_chain[i - 1]
            if transition.from_state != expected_from:
                logger.error(
                    f"Transition {transition.id} from_state mismatch: "
                    f"expected {expected_from}, got {transition.from_state}"
                )
                return False
            
            # Verify transition integrity
            if not transition.verify_integrity():
                logger.error(f"Transition {transition.id} integrity check failed")
                return False
        
        return True
    
    def serialize(self) -> bytes:
        """Serialize the store to bytes for hashing."""
        data = {
            "latest_state": self.latest_state,
            "state_chain": self.state_chain,
            "transitions": {
                tid: t.model_dump() for tid, t in self.transitions.items()
            },
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")
    
    def compute_root_hash(self) -> str:
        """Compute a root hash of all transitions for state verification."""
        return hashlib.sha256(self.serialize()).hexdigest()
    
    @classmethod
    def from_serialized(cls, data: bytes) -> "TransitionStore":
        """Deserialize from bytes."""
        obj = json.loads(data.decode("utf-8"))
        
        store = cls()
        store.latest_state = obj.get("latest_state", cls.GENESIS_HASH)
        store.state_chain = obj.get("state_chain", [cls.GENESIS_HASH])
        
        for tid, tdata in obj.get("transitions", {}).items():
            store.transitions[tid] = Transition(**tdata)
        
        return store
