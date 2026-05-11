"""
Unit tests for the MemoryDAG.
"""

import pytest
from mingseal_immutable_memory.core.dag import (
    MemoryDAG,
    CycleDetectedError,
)
from mingseal_immutable_memory.models.memory_node import EdgeType


class TestMemoryDAG:
    """Tests for the MemoryDAG class."""
    
    def test_initialization(self):
        """Test DAG initialization."""
        dag = MemoryDAG()
        
        assert dag.count_nodes() == 0
        assert dag.count_edges() == 0
    
    def test_add_node(self):
        """Test adding a node to the DAG."""
        dag = MemoryDAG()
        
        node = dag.add_node(
            content="First memory",
            transition_id="t1",
        )
        
        assert node.id.startswith("mem_")
        assert dag.count_nodes() == 1
        assert dag.get_node(node.id) is not None
    
    def test_add_node_with_parents(self):
        """Test adding a node with parent references."""
        dag = MemoryDAG()
        
        parent = dag.add_node(
            content="Parent memory",
            transition_id="t1",
        )
        
        child = dag.add_node(
            content="Child memory",
            transition_id="t2",
            parents=[parent.id],
        )
        
        assert dag.count_nodes() == 2
        assert dag.count_edges() == 1
        assert child.parents == [parent.id]
    
    def test_get_parents(self):
        """Test retrieving parent nodes."""
        dag = MemoryDAG()
        
        parent1 = dag.add_node(content="Parent 1", transition_id="t1")
        parent2 = dag.add_node(content="Parent 2", transition_id="t2")
        
        child = dag.add_node(
            content="Child",
            transition_id="t3",
            parents=[parent1.id, parent2.id],
        )
        
        parents = dag.get_parents(child.id)
        assert len(parents) == 2
    
    def test_get_children(self):
        """Test retrieving child nodes."""
        dag = MemoryDAG()
        
        parent = dag.add_node(content="Parent", transition_id="t1")
        child1 = dag.add_node(content="Child 1", transition_id="t2", parents=[parent.id])
        child2 = dag.add_node(content="Child 2", transition_id="t3", parents=[parent.id])
        
        children = dag.get_children(parent.id)
        assert len(children) == 2
    
    def test_cycle_detection(self):
        """Test that cycles are detected and prevented."""
        dag = MemoryDAG()
        
        node_a = dag.add_node(content="A", transition_id="t1")
        node_b = dag.add_node(content="B", transition_id="t2", parents=[node_a.id])
        
        # Try to create edge that would form cycle: C -> B -> A -> C
        from mingseal_immutable_memory.models.memory_node import create_memory_edge
        edge = create_memory_edge(
            source=node_a.id,
            target=node_b.id,
            edge_type=EdgeType.INFERENCE,
            transition_id="t3",
        )
        
        # This should raise CycleDetectedError
        with pytest.raises(CycleDetectedError):
            dag.add_edge(edge)
    
    def test_trace_back(self):
        """Test tracing back through ancestors."""
        dag = MemoryDAG()
        
        root = dag.add_node(content="Root", transition_id="t1")
        level1 = dag.add_node(content="Level 1", transition_id="t2", parents=[root.id])
        level2 = dag.add_node(content="Level 2", transition_id="t3", parents=[level1.id])
        level3 = dag.add_node(content="Level 3", transition_id="t4", parents=[level2.id])
        
        path = dag.trace_back(level3.id)
        
        assert len(path) == 4
        assert path[0].id == level3.id
        assert path[-1].id == root.id
    
    def test_topological_sort(self):
        """Test topological sorting."""
        dag = MemoryDAG()
        
        # Create a diamond structure
        top = dag.add_node(content="Top", transition_id="t1")
        left = dag.add_node(content="Left", transition_id="t2", parents=[top.id])
        right = dag.add_node(content="Right", transition_id="t3", parents=[top.id])
        bottom = dag.add_node(
            content="Bottom",
            transition_id="t4",
            parents=[left.id, right.id],
        )
        
        sorted_nodes = dag.topological_sort()
        
        # Top should come before its children
        top_idx = next(i for i, n in enumerate(sorted_nodes) if n.id == top.id)
        left_idx = next(i for i, n in enumerate(sorted_nodes) if n.id == left.id)
        right_idx = next(i for i, n in enumerate(sorted_nodes) if n.id == right.id)
        bottom_idx = next(i for i, n in enumerate(sorted_nodes) if n.id == bottom.id)
        
        assert top_idx < left_idx
        assert top_idx < right_idx
        assert left_idx < bottom_idx
        assert right_idx < bottom_idx
    
    def test_scope_indexing(self):
        """Test scope-based node indexing."""
        dag = MemoryDAG()
        
        dag.add_node(content="Node 1", transition_id="t1", scope="/infrastructure")
        dag.add_node(content="Node 2", transition_id="t2", scope="/infrastructure/compute")
        dag.add_node(content="Node 3", transition_id="t3", scope="/knowledge")
        
        infra_nodes = dag.get_by_scope("/infrastructure", recursive=True)
        assert len(infra_nodes) == 2
        
        compute_nodes = dag.get_by_scope("/infrastructure/compute", recursive=False)
        assert len(compute_nodes) == 1
    
    def test_verify_acyclic(self):
        """Test DAG acyclicity verification."""
        dag = MemoryDAG()
        
        dag.add_node(content="A", transition_id="t1")
        dag.add_node(content="B", transition_id="t2")
        node_ids = list(dag.nodes.keys())
        dag.add_node(content="C", transition_id="t3", parents=[node_ids[0]] if node_ids else [])
        
        assert dag.verify_acyclic() is True
    
    def test_serialization(self):
        """Test DAG serialization and deserialization."""
        dag = MemoryDAG()
        
        node1 = dag.add_node(content="Memory 1", transition_id="t1")
        node2 = dag.add_node(content="Memory 2", transition_id="t2", parents=[node1.id])
        
        # Serialize
        data = dag.serialize()
        
        # Deserialize
        restored = MemoryDAG.from_serialized(data)
        
        assert restored.count_nodes() == dag.count_nodes()
        assert restored.count_edges() == dag.count_edges()
    
    def test_get_roots(self):
        """Test getting root nodes."""
        dag = MemoryDAG()
        
        root1 = dag.add_node(content="Root 1", transition_id="t1")
        root2 = dag.add_node(content="Root 2", transition_id="t2")
        dag.add_node(content="Child", transition_id="t3", parents=[root1.id])
        
        roots = dag.get_roots()
        assert len(roots) == 2
        assert root1 in roots
        assert root2 in roots
    
    def test_get_stats(self):
        """Test getting DAG statistics."""
        dag = MemoryDAG()
        
        dag.add_node(content="A", transition_id="t1")
        dag.add_node(content="B", transition_id="t2")
        dag.add_node(content="C", transition_id="t3")
        
        stats = dag.get_stats()
        
        assert stats["nodes"] == 3
        assert stats["roots"] == 3
        assert stats["edges"] == 0
