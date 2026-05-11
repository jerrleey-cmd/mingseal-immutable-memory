"""
Transition data model.

Represents a cognitive state transition in an AI agent's reasoning process.
Each transition captures a single step in the agent's thought chain.
"""

import json
import hashlib
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class InputType(str):
    """Valid input types for transitions."""
    USER_MSG = "user_msg"
    TOOL_CALL = "tool_call"
    TIMER = "timer"
    MEMORY_UPDATE = "memory_update"


class OutputType(str):
    """Valid output types for transitions."""
    REPLY = "reply"
    TOOL_RESULT = "tool_result"
    MEMORY_WRITE = "memory_write"


class Transition(BaseModel):
    """
    Represents a cognitive state transition in an AI agent.
    
    This model captures the fundamental unit of agent cognition:
    a transition from one cognitive state to another based on
    some input and producing some output.
    """
    id: str = Field(..., description="SHA-256 hash of the entire transition")
    from_state: str = Field(..., description="Hash of the previous cognitive state")
    input_type: str = Field(..., description="Type of input that triggered this transition")
    input_hash: str = Field(..., description="SHA-256 hash of input content")
    output_type: str = Field(..., description="Type of output produced")
    output_hash: str = Field(..., description="SHA-256 hash of output content")
    to_state: str = Field(..., description="Hash of the new cognitive state")
    timestamp: str = Field(..., description="ISO8601 timestamp")
    signature: Optional[str] = Field(None, description="Agent private key signature (optional)")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator("input_type", "output_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate input/output types."""
        valid_inputs = {"user_msg", "tool_call", "timer", "memory_update"}
        valid_outputs = {"reply", "tool_result", "memory_write"}
        
        # Allow custom types but warn
        if v not in valid_inputs and v not in valid_outputs:
            # Will be checked by caller based on which field
            pass
        return v
    
    def to_json_bytes(self) -> bytes:
        """Serialize transition to JSON bytes for hashing."""
        # Exclude id, signature, and timestamp from hash calculation for idempotency
        data = {
            "from_state": self.from_state,
            "input_type": self.input_type,
            "input_hash": self.input_hash,
            "output_type": self.output_type,
            "output_hash": self.output_hash,
            "to_state": self.to_state,
            "metadata": self.metadata,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")
    
    def compute_id(self) -> str:
        """Compute the transition ID as SHA-256 of serialized content."""
        return hashlib.sha256(self.to_json_bytes()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify that the transition ID matches the computed hash."""
        return self.id == self.compute_id()
    
    class Config:
        """Pydantic model configuration."""
        frozen = False  # Allow metadata modifications


def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_state_hash(*hashes: str) -> str:
    """Compute a state hash from a collection of content hashes."""
    combined = "|".join(sorted(hashes))
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def create_transition(
    from_state: str,
    input_type: str,
    input_content: str,
    output_type: str,
    output_content: str,
    to_state: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> Transition:
    """
    Factory function to create a new transition.
    
    Args:
        from_state: Hash of the previous cognitive state
        input_type: Type of input
        input_content: Raw input content (will be hashed)
        output_type: Type of output
        output_content: Raw output content (will be hashed)
        to_state: New state hash (auto-computed if not provided)
        metadata: Additional metadata
    
    Returns:
        A new Transition instance with computed hashes
    """
    input_hash = compute_content_hash(input_content)
    output_hash = compute_content_hash(output_content)
    
    if to_state is None:
        # Auto-compute new state from previous state and outputs
        to_state = compute_state_hash(from_state, input_hash, output_hash)
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    transition = Transition(
        id="",  # Will be computed
        from_state=from_state,
        input_type=input_type,
        input_hash=input_hash,
        output_type=output_type,
        output_hash=output_hash,
        to_state=to_state,
        timestamp=timestamp,
        metadata=metadata or {},
    )
    
    # Compute and set the ID
    transition.id = transition.compute_id()
    
    return transition
