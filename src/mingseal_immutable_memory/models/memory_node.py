"""
Memory Node and Edge data models.

Represents the DAG-based knowledge graph structure for AI agent memory.
Each node is an immutable record, edges represent derivation relationships.
"""

import hashlib
from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class EdgeType(str, Enum):
    """Types of edges in the memory DAG."""
    INFERENCE = "inference"       # Logical derivation
    CORRECTION = "correction"     # Rectification of previous belief
    EXTENSION = "extension"      # Building upon existing knowledge
    CONTRADICTION = "contradiction"  # Contradicts previous knowledge


class AccessLevel(int):
    """Memory access control levels."""
    PUBLIC = 0      # Anyone can access
    INTERNAL = 1   # Internal agents only
    CONFIDENTIAL = 2  # Restricted access


class MemoryNode(BaseModel):
    """
    Represents an immutable memory node in the DAG.
    
    Each node contains content that was captured during an agent's
    cognitive process, linked to previous nodes via parent references.
    """
    id: str = Field(..., description="Node ID in format 'mem_' + SHA-256")
    content_hash: str = Field(..., description="SHA-256 hash of the content")
    parents: List[str] = Field(default_factory=list, description="Parent node IDs")
    transition_id: str = Field(..., description="Associated transition ID")
    merkle_root: Optional[str] = Field(None, description="Merkle batch root")
    merkle_proof: dict = Field(default_factory=dict, description="Merkle inclusion proof")
    anchor_id: Optional[str] = Field(None, description="Anchor record ID")
    access_level: int = Field(default=0, description="Access control level (0=public, 1=internal, 2=confidential)")
    created_at: str = Field(..., description="ISO8601 creation timestamp")
    scope: str = Field(default="/", description="Hierarchical path for organization")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, v: int) -> int:
        """Ensure access level is valid."""
        if v < 0 or v > 2:
            raise ValueError(f"Access level must be 0-2, got {v}")
        return v
    
    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        """Ensure scope starts with /."""
        if not v.startswith("/"):
            v = "/" + v
        return v
    
    def to_json_bytes(self) -> bytes:
        """Serialize to JSON bytes for hashing."""
        import json
        data = {
            "content_hash": self.content_hash,
            "parents": self.parents,
            "transition_id": self.transition_id,
            "created_at": self.created_at,
            "scope": self.scope,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")
    
    def verify_integrity(self) -> bool:
        """Verify that the node ID matches the computed hash."""
        expected_id = self.compute_id()
        return self.id == expected_id
    
    @staticmethod
    def compute_id_from_content(content_hash: str, timestamp: str) -> str:
        """Compute node ID from content hash and timestamp."""
        data = f"{content_hash}:{timestamp}".encode("utf-8")
        return "mem_" + hashlib.sha256(data).hexdigest()
    
    def compute_id(self) -> str:
        """Compute the node ID."""
        return self.compute_id_from_content(self.content_hash, self.created_at)


class MemoryEdge(BaseModel):
    """
    Represents a directed edge in the memory DAG.
    
    Edges connect child nodes to parent nodes, establishing
    the derivation relationship between memories.
    """
    id: str = Field(..., description="Edge ID")
    source: str = Field(..., description="Child node ID")
    target: str = Field(..., description="Parent node ID")
    edge_type: EdgeType = Field(..., description="Type of derivation relationship")
    transition_id: str = Field(..., description="Transition that created this edge")
    created_at: str = Field(..., description="ISO8601 creation timestamp")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")
    
    def to_json_bytes(self) -> bytes:
        """Serialize to JSON bytes for hashing."""
        import json
        data = {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "transition_id": self.transition_id,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")
    
    def compute_id(self) -> str:
        """Compute the edge ID."""
        return hashlib.sha256(self.to_json_bytes()).hexdigest()


def create_memory_node(
    content: str,
    transition_id: str,
    parents: Optional[List[str]] = None,
    scope: str = "/",
    access_level: int = 0,
    metadata: Optional[dict] = None,
) -> MemoryNode:
    """
    Factory function to create a new memory node.
    
    Args:
        content: Raw content to store (will be hashed)
        transition_id: Associated transition ID
        parents: List of parent node IDs
        scope: Hierarchical path for organization
        access_level: Access control level
        metadata: Additional metadata
    
    Returns:
        A new MemoryNode instance with computed hashes
    """
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    timestamp = datetime.utcnow().isoformat() + "Z"
    node_id = MemoryNode.compute_id_from_content(content_hash, timestamp)
    
    return MemoryNode(
        id=node_id,
        content_hash=content_hash,
        parents=parents or [],
        transition_id=transition_id,
        merkle_root=None,
        merkle_proof={},
        anchor_id=None,
        access_level=access_level,
        created_at=timestamp,
        scope=scope,
        metadata=metadata or {},
    )


def create_memory_edge(
    source: str,
    target: str,
    edge_type: EdgeType,
    transition_id: str,
    metadata: Optional[dict] = None,
) -> MemoryEdge:
    """
    Factory function to create a new memory edge.
    
    Args:
        source: Child node ID
        target: Parent node ID
        edge_type: Type of derivation relationship
        transition_id: Transition that created this edge
        metadata: Additional metadata
    
    Returns:
        A new MemoryEdge instance
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    edge = MemoryEdge(
        id="",  # Will be computed
        source=source,
        target=target,
        edge_type=edge_type,
        transition_id=transition_id,
        created_at=timestamp,
        metadata=metadata or {},
    )
    
    edge.id = edge.compute_id()
    return edge
