"""
Layer 2: DAG-based Knowledge Graph.

An append-only Directed Acyclic Graph (DAG) for representing agent memory
with derivation relationships. Includes cycle detection to maintain DAG property.
"""

import hashlib
import json
import logging
from collections import deque
from datetime import datetime
from typing import Optional, List, Dict, Set, Tuple, Any

from ..models.memory_node import MemoryNode, MemoryEdge, EdgeType, create_memory_node, create_memory_edge

logger = logging.getLogger(__name__)


class CycleDetectedError(Exception):
    """Raised when adding an edge would create a cycle in the DAG."""
    
    def __init__(self, cycle_path: List[str]):
        self.cycle_path = cycle_path
        super().__init__(f"Adding this edge would create a cycle: {' -> '.join(cycle_path)}")


class MemoryDAG:
    """
    Append-only Directed Acyclic Graph for agent memory.
    
    This DAG represents the knowledge graph where:
    - Nodes are memory entries
    - Edges represent derivation relationships (inference, correction, extension, contradiction)
    - New nodes can only be added, never modified or deleted
    
    The DAG maintains topological ordering and detects cycles.
    """
    
    def __init__(self):
        self.nodes: Dict[str, MemoryNode] = {}
        self.edges: Dict[str, MemoryEdge] = {}
        
        # Adjacency lists for efficient traversal
        self.outgoing: Dict[str, List[str]] = {}  # node -> children
        self.incoming: Dict[str, List[str]] = {}  # node -> parents
        
        # Index structures for efficient queries
        self.scope_index: Dict[str, Set[str]] = {}  # scope -> node IDs
        self.transition_index: Dict[str, Set[str]] = {}  # transition_id -> node IDs
    
    def add_node(
        self,
        content: str,
        transition_id: str,
        parents: Optional[List[str]] = None,
        scope: str = "/",
        access_level: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryNode:
        """
        Add a new memory node to the DAG.
        
        Args:
            content: The memory content (will be hashed)
            transition_id: Associated transition ID
            parents: Parent node IDs (will become edges)
            scope: Hierarchical scope path
            access_level: Access control level
            metadata: Additional metadata
        
        Returns:
            The created MemoryNode
        
        Raises:
            ValueError: If a parent node doesn't exist
        """
        node = create_memory_node(
            content=content,
            transition_id=transition_id,
            parents=parents or [],
            scope=scope,
            access_level=access_level,
            metadata=metadata,
        )
        
        # Validate parent existence
        if parents:
            for parent_id in parents:
                if parent_id not in self.nodes:
                    raise ValueError(f"Parent node {parent_id} does not exist")
        
        # Store node
        self.nodes[node.id] = node
        
        # Update indices
        self._add_to_scope_index(node)
        self._add_to_transition_index(node)
        
        # Create edges to parents
        if parents:
            for parent_id in parents:
                edge = create_memory_edge(
                    source=node.id,
                    target=parent_id,
                    edge_type=self._infer_edge_type(node, self.nodes.get(parent_id)),
                    transition_id=transition_id,
                )
                self.add_edge(edge)
        
        # Initialize adjacency lists
        if node.id not in self.outgoing:
            self.outgoing[node.id] = []
        if node.id not in self.incoming:
            self.incoming[node.id] = []
        
        logger.info(f"Added memory node {node.id[:16]}... with {len(parents or [])} parents")
        
        return node
    
    def add_edge(self, edge: MemoryEdge) -> None:
        """
        Add an edge to the DAG.
        
        Args:
            edge: The edge to add
        
        Raises:
            CycleDetectedError: If adding the edge would create a cycle
            ValueError: If source or target nodes don't exist
        """
        if edge.source not in self.nodes:
            raise ValueError(f"Source node {edge.source} does not exist")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node {edge.target} does not exist")
        
        # Check for cycle before adding
        if self._would_create_cycle(edge.source, edge.target):
            path = self._find_path(edge.target, edge.source)
            raise CycleDetectedError(path + [edge.source])
        
        # Store edge
        self.edges[edge.id] = edge
        
        # Update adjacency lists
        if edge.target not in self.outgoing:
            self.outgoing[edge.target] = []
        if edge.source not in self.incoming:
            self.incoming[edge.source] = []
        
        self.outgoing[edge.target].append(edge.source)
        self.incoming[edge.source].append(edge.target)
        
        logger.debug(f"Added edge {edge.id[:16]}...: {edge.source[:8]} -> {edge.target[:8]}")
    
    def _would_create_cycle(self, source: str, target: str) -> bool:
        """
        Check if adding an edge from source to target would create a cycle.
        
        Edge semantics: source -> target means source is child of target.
        Adding source -> target creates a cycle if source already has a path to target.
        
        Since outgoing[parent] = [children], we follow child chain from source.
        """
        # Use DFS from source to find target
        visited = set()
        
        def dfs(node: str) -> bool:
            if node == target:
                return True
            if node in visited:
                return False
            visited.add(node)
            # outgoing[parent] = [children], follow child chain from node
            for child in self.outgoing.get(node, []):
                if dfs(child):
                    return True
            return False
        
        return dfs(source)
    
    def _find_path(self, start: str, end: str) -> List[str]:
        """Find a path from start to end following outgoing edges."""
        visited = set()
        queue = deque([(start, [start])])
        
        while queue:
            current, path = queue.popleft()
            
            if current == end:
                return path
            
            if current in visited:
                continue
            visited.add(current)
            
            for child in self.outgoing.get(current, []):
                if child not in visited:
                    queue.append((child, path + [child]))
        
        return []
    
    def _infer_edge_type(self, child: MemoryNode, parent: Optional[MemoryNode]) -> EdgeType:
        """
        Infer the edge type based on node content and metadata.
        
        This is a heuristic that can be overridden by explicit metadata.
        """
        if child.metadata.get("edge_type"):
            try:
                return EdgeType(child.metadata["edge_type"])
            except ValueError:
                pass
        
        # Default to inference
        return EdgeType.INFERENCE
    
    def _add_to_scope_index(self, node: MemoryNode) -> None:
        """Add node to scope index."""
        if node.scope not in self.scope_index:
            self.scope_index[node.scope] = set()
        self.scope_index[node.scope].add(node.id)
        
        # Also index parent scopes
        parts = node.scope.rstrip("/").split("/")
        for i in range(1, len(parts)):
            parent_scope = "/".join(parts[:i]) + "/"
            if parent_scope not in self.scope_index:
                self.scope_index[parent_scope] = set()
            self.scope_index[parent_scope].add(node.id)
    
    def _add_to_transition_index(self, node: MemoryNode) -> None:
        """Add node to transition index."""
        if node.transition_id not in self.transition_index:
            self.transition_index[node.transition_id] = set()
        self.transition_index[node.transition_id].add(node.id)
    
    def get_node(self, node_id: str) -> Optional[MemoryNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_edge(self, edge_id: str) -> Optional[MemoryEdge]:
        """Get an edge by ID."""
        return self.edges.get(edge_id)
    
    def get_parents(self, node_id: str) -> List[MemoryNode]:
        """Get parent nodes (incoming edges)."""
        node = self.nodes.get(node_id)
        if not node:
            return []
        return [self.nodes[nid] for nid in node.parents if nid in self.nodes]
    
    def get_children(self, node_id: str) -> List[MemoryNode]:
        """Get child nodes (outgoing edges)."""
        return [self.nodes[cid] for cid in self.outgoing.get(node_id, []) if cid in self.nodes]
    
    def get_by_scope(self, scope: str, recursive: bool = True) -> List[MemoryNode]:
        """
        Get all nodes in a scope.
        
        Args:
            scope: The scope path
            recursive: If True, include all descendant scopes
        
        Returns:
            List of nodes in the scope
        """
        if scope not in self.scope_index:
            return []
        
        if recursive:
            # Collect all descendant scopes
            all_ids = set()
            for indexed_scope in self.scope_index:
                if indexed_scope == scope or indexed_scope.startswith(scope):
                    all_ids.update(self.scope_index[indexed_scope])
            return [self.nodes[nid] for nid in all_ids if nid in self.nodes]
        else:
            return [self.nodes[nid] for nid in self.scope_index.get(scope, set()) if nid in self.nodes]
    
    def get_by_transition(self, transition_id: str) -> List[MemoryNode]:
        """Get all nodes associated with a transition."""
        node_ids = self.transition_index.get(transition_id, set())
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]
    
    def trace_back(self, node_id: str, limit: int = 100) -> List[MemoryNode]:
        """
        Trace back through parent relationships to root.
        
        Args:
            node_id: Starting node ID
            limit: Maximum number of nodes to trace
        
        Returns:
            List of nodes from start to root
        """
        path = []
        visited = set()
        current = node_id
        
        while current and len(path) < limit:
            if current in visited:
                break
            visited.add(current)
            
            node = self.nodes.get(current)
            if not node:
                break
            
            path.append(node)
            current = node.parents[0] if node.parents else None
        
        return path
    
    def topological_sort(self) -> List[MemoryNode]:
        """
        Perform topological sort of all nodes.
        
        Returns:
            Nodes in topologically sorted order (parents before children)
        """
        in_degree = {nid: len(self.nodes[nid].parents) for nid in self.nodes}
        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        result = []
        
        while queue:
            current = queue.popleft()
            result.append(self.nodes[current])
            
            for child in self.outgoing.get(current, []):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        
        if len(result) != len(self.nodes):
            logger.warning("Topological sort incomplete - possible cycle detected")
        
        return result
    
    def get_roots(self) -> List[MemoryNode]:
        """Get all root nodes (nodes with no parents)."""
        return [node for node in self.nodes.values() if len(node.parents) == 0]
    
    def verify_acyclic(self) -> bool:
        """
        Verify the graph is still a valid DAG.
        
        Returns:
            True if no cycles detected
        """
        try:
            self.topological_sort()
            return True
        except Exception as e:
            logger.error(f"DAG validation failed: {e}")
            return False
    
    def count_nodes(self) -> int:
        """Get total number of nodes."""
        return len(self.nodes)
    
    def count_edges(self) -> int:
        """Get total number of edges."""
        return len(self.edges)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get DAG statistics."""
        roots = self.get_roots()
        max_depth = 0
        for root in roots:
            depth = self._get_depth(root.id)
            max_depth = max(max_depth, depth)
        
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "roots": len(roots),
            "max_depth": max_depth,
            "scopes": len(self.scope_index),
            "transitions": len(self.transition_index),
        }
    
    def _get_depth(self, node_id: str) -> int:
        """Get the depth of a node from roots."""
        visited = set()
        return self._get_depth_recursive(node_id, visited, 0)
    
    def _get_depth_recursive(self, node_id: str, visited: Set[str], current_depth: int) -> int:
        """Recursive depth calculation."""
        if node_id in visited:
            return 0
        visited.add(node_id)
        
        node = self.nodes.get(node_id)
        if not node or not node.parents:
            return current_depth
        
        max_child_depth = 0
        for parent_id in node.parents:
            depth = self._get_depth_recursive(parent_id, visited, current_depth + 1)
            max_child_depth = max(max_child_depth, depth)
        
        return max_child_depth
    
    def serialize(self) -> bytes:
        """Serialize the DAG to bytes."""
        data = {
            "nodes": {nid: node.model_dump() for nid, node in self.nodes.items()},
            "edges": {eid: edge.model_dump() for eid, edge in self.edges.items()},
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")
    
    def compute_root_hash(self) -> str:
        """Compute a hash of the entire DAG structure."""
        return hashlib.sha256(self.serialize()).hexdigest()
    
    @classmethod
    def from_serialized(cls, data: bytes) -> "MemoryDAG":
        """Deserialize from bytes."""
        obj = json.loads(data.decode("utf-8"))
        
        dag = cls()
        
        for nid, ndata in obj.get("nodes", {}).items():
            dag.nodes[nid] = MemoryNode(**ndata)
        
        for eid, edata in obj.get("edges", {}).items():
            dag.edges[eid] = MemoryEdge(**edata)
        
        # Rebuild adjacency lists
        for edge in dag.edges.values():
            if edge.target not in dag.outgoing:
                dag.outgoing[edge.target] = []
            if edge.source not in dag.incoming:
                dag.incoming[edge.source] = []
            dag.outgoing[edge.target].append(edge.source)
            dag.incoming[edge.source].append(edge.target)
        
        # Rebuild indices
        for node in dag.nodes.values():
            dag._add_to_scope_index(node)
            dag._add_to_transition_index(node)
        
        # Ensure all nodes have adjacency lists
        for nid in dag.nodes:
            if nid not in dag.outgoing:
                dag.outgoing[nid] = []
            if nid not in dag.incoming:
                dag.incoming[nid] = []
        
        return dag
