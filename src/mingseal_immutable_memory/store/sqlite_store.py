"""
SQLite Storage with FTS5 Full-Text Search.

Provides persistent storage for transitions, memory nodes, edges,
and anchor records. Includes FTS5 for efficient content search.
"""

import aiosqlite
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from ..models.transition import Transition
from ..models.memory_node import MemoryNode, MemoryEdge
from ..models.anchor_result import AnchorResult

logger = logging.getLogger(__name__)


class SQLiteStore:
    """
    SQLite-based storage with FTS5 full-text search.
    
    Tables:
    - transitions: Cognitive state transitions
    - memory_nodes: DAG memory nodes
    - memory_edges: DAG edges
    - anchor_records: Anchoring results
    - state_snapshots: Cognitive state snapshots
    """
    
    def __init__(self, db_path: str):
        """
        Initialize SQLite store.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None
    
    async def connect(self) -> None:
        """Establish database connection and create tables."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        
        # Enable foreign keys
        await self._conn.execute("PRAGMA foreign_keys = ON")
        
        # Create tables
        await self._create_tables()
        
        # Create FTS5 virtual table
        await self._create_fts()
        
        logger.info(f"Connected to SQLite database at {self.db_path}")
    
    async def close(self) -> None:
        """Close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("Database connection closed")
    
    async def _create_tables(self) -> None:
        """Create all database tables."""
        # Transitions table
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS transitions (
                id TEXT PRIMARY KEY,
                from_state TEXT NOT NULL,
                input_type TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                output_type TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                to_state TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                signature TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Memory nodes table
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS memory_nodes (
                id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                transition_id TEXT NOT NULL,
                merkle_root TEXT,
                merkle_proof TEXT,
                anchor_id TEXT,
                access_level INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                scope TEXT DEFAULT '/',
                metadata TEXT,
                content_preview TEXT,
                FOREIGN KEY (transition_id) REFERENCES transitions(id)
            )
        """)
        
        # Memory edges table
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS memory_edges (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                transition_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (source) REFERENCES memory_nodes(id),
                FOREIGN KEY (target) REFERENCES memory_nodes(id)
            )
        """)
        
        # Anchor records table
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS anchor_records (
                anchor_id TEXT PRIMARY KEY,
                backend TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                tx_id TEXT,
                timestamp TEXT NOT NULL,
                block_height INTEGER,
                verified INTEGER DEFAULT 0,
                proof_data TEXT,
                error TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # State snapshots table
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS state_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                state_root TEXT NOT NULL,
                previous_snapshot_id TEXT,
                memory_files TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transitions_to_state ON transitions(to_state)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_transition ON memory_nodes(transition_id)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_scope ON memory_nodes(scope)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_anchor ON memory_nodes(anchor_id)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_edges_source ON memory_edges(source)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_edges_target ON memory_edges(target)"
        )
        
        await self._conn.commit()
    
    async def _create_fts(self) -> None:
        """Create FTS5 virtual table for full-text search."""
        await self._conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                node_id,
                content,
                content_preview,
                scope,
                tokenize='porter unicode61'
            )
        """)
        await self._conn.commit()
    
    # ==================== Transition Operations ====================
    
    async def save_transition(self, transition: Transition) -> None:
        """Save a transition to the database."""
        await self._conn.execute("""
            INSERT OR REPLACE INTO transitions 
            (id, from_state, input_type, input_hash, output_type, output_hash, 
             to_state, timestamp, signature, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            transition.id,
            transition.from_state,
            transition.input_type,
            transition.input_hash,
            transition.output_type,
            transition.output_hash,
            transition.to_state,
            transition.timestamp,
            transition.signature,
            json.dumps(transition.metadata),
        ))
        await self._conn.commit()
    
    async def get_transition(self, transition_id: str) -> Optional[Transition]:
        """Get a transition by ID."""
        cursor = await self._conn.execute(
            "SELECT * FROM transitions WHERE id = ?",
            (transition_id,)
        )
        row = await cursor.fetchone()
        
        if row is None:
            return None
        
        return Transition(
            id=row["id"],
            from_state=row["from_state"],
            input_type=row["input_type"],
            input_hash=row["input_hash"],
            output_type=row["output_type"],
            output_hash=row["output_hash"],
            to_state=row["to_state"],
            timestamp=row["timestamp"],
            signature=row["signature"],
            metadata=json.loads(row["metadata"] or "{}"),
        )
    
    async def get_transitions_since(
        self,
        since_state: Optional[str] = None,
        limit: int = 100,
    ) -> List[Transition]:
        """Get transitions since a given state."""
        if since_state:
            cursor = await self._conn.execute("""
                SELECT * FROM transitions 
                WHERE to_state > ? 
                ORDER BY timestamp
                LIMIT ?
            """, (since_state, limit))
        else:
            cursor = await self._conn.execute("""
                SELECT * FROM transitions 
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        rows = await cursor.fetchall()
        
        return [
            Transition(
                id=row["id"],
                from_state=row["from_state"],
                input_type=row["input_type"],
                input_hash=row["input_hash"],
                output_type=row["output_type"],
                output_hash=row["output_hash"],
                to_state=row["to_state"],
                timestamp=row["timestamp"],
                signature=row["signature"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    async def count_transitions(self) -> int:
        """Get total number of transitions."""
        cursor = await self._conn.execute("SELECT COUNT(*) FROM transitions")
        row = await cursor.fetchone()
        return row[0] if row else 0
    
    # ==================== Memory Node Operations ====================
    
    async def save_memory_node(
        self,
        node: MemoryNode,
        content: Optional[str] = None,
    ) -> None:
        """Save a memory node to the database."""
        # Generate content preview for search
        preview = content[:500] if content else None
        
        await self._conn.execute("""
            INSERT OR REPLACE INTO memory_nodes 
            (id, content_hash, transition_id, merkle_root, merkle_proof, 
             anchor_id, access_level, created_at, scope, metadata, content_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            node.id,
            node.content_hash,
            node.transition_id,
            node.merkle_root,
            json.dumps(node.merkle_proof),
            node.anchor_id,
            node.access_level,
            node.created_at,
            node.scope,
            json.dumps(node.metadata),
            preview,
        ))
        
        # Update FTS index
        if content:
            await self._conn.execute("""
                INSERT OR REPLACE INTO memory_fts (node_id, content, content_preview, scope)
                VALUES (?, ?, ?, ?)
            """, (node.id, content, preview, node.scope))
        
        await self._conn.commit()
    
    async def get_memory_node(self, node_id: str) -> Optional[MemoryNode]:
        """Get a memory node by ID."""
        cursor = await self._conn.execute(
            "SELECT * FROM memory_nodes WHERE id = ?",
            (node_id,)
        )
        row = await cursor.fetchone()
        
        if row is None:
            return None
        
        return MemoryNode(
            id=row["id"],
            content_hash=row["content_hash"],
            transition_id=row["transition_id"],
            merkle_root=row["merkle_root"],
            merkle_proof=json.loads(row["merkle_proof"] or "{}"),
            anchor_id=row["anchor_id"],
            access_level=row["access_level"],
            created_at=row["created_at"],
            scope=row["scope"],
            metadata=json.loads(row["metadata"] or "{}"),
        )
    
    async def get_memory_content(self, node_id: str) -> Optional[str]:
        """Get the full content of a memory node (from FTS table)."""
        cursor = await self._conn.execute(
            "SELECT content FROM memory_fts WHERE node_id = ?",
            (node_id,)
        )
        row = await cursor.fetchone()
        return row["content"] if row else None
    
    async def search_memory(
        self,
        query: str,
        scope: Optional[str] = None,
        limit: int = 10,
    ) -> List[MemoryNode]:
        """
        Search memory nodes using FTS5.
        
        Args:
            query: Search query
            scope: Optional scope filter
            limit: Maximum results
        
        Returns:
            List of matching memory nodes
        """
        # Use FTS5 for search
        if scope:
            sql = """
                SELECT m.* FROM memory_nodes m
                JOIN memory_fts f ON m.id = f.node_id
                WHERE memory_fts MATCH ?
                AND m.scope LIKE ?
                ORDER BY rank
                LIMIT ?
            """
            cursor = await self._conn.execute(
                sql,
                (query, scope + "%", limit)
            )
        else:
            sql = """
                SELECT m.* FROM memory_nodes m
                JOIN memory_fts f ON m.id = f.node_id
                WHERE memory_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """
            cursor = await self._conn.execute(sql, (query, limit))
        
        rows = await cursor.fetchall()
        
        return [
            MemoryNode(
                id=row["id"],
                content_hash=row["content_hash"],
                transition_id=row["transition_id"],
                merkle_root=row["merkle_root"],
                merkle_proof=json.loads(row["merkle_proof"] or "{}"),
                anchor_id=row["anchor_id"],
                access_level=row["access_level"],
                created_at=row["created_at"],
                scope=row["scope"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    async def get_nodes_by_scope(
        self,
        scope: str,
        recursive: bool = True,
        limit: int = 100,
    ) -> List[MemoryNode]:
        """Get nodes by scope."""
        if recursive:
            pattern = scope + "%"
        else:
            pattern = scope
        
        cursor = await self._conn.execute("""
            SELECT * FROM memory_nodes 
            WHERE scope LIKE ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (pattern, limit))
        
        rows = await cursor.fetchall()
        
        return [
            MemoryNode(
                id=row["id"],
                content_hash=row["content_hash"],
                transition_id=row["transition_id"],
                merkle_root=row["merkle_root"],
                merkle_proof=json.loads(row["merkle_proof"] or "{}"),
                anchor_id=row["anchor_id"],
                access_level=row["access_level"],
                created_at=row["created_at"],
                scope=row["scope"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    async def get_nodes_by_transition(
        self,
        transition_id: str,
    ) -> List[MemoryNode]:
        """Get all nodes associated with a transition."""
        cursor = await self._conn.execute("""
            SELECT * FROM memory_nodes WHERE transition_id = ?
        """, (transition_id,))
        
        rows = await cursor.fetchall()
        
        return [
            MemoryNode(
                id=row["id"],
                content_hash=row["content_hash"],
                transition_id=row["transition_id"],
                merkle_root=row["merkle_root"],
                merkle_proof=json.loads(row["merkle_proof"] or "{}"),
                anchor_id=row["anchor_id"],
                access_level=row["access_level"],
                created_at=row["created_at"],
                scope=row["scope"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    async def count_memory_nodes(self) -> int:
        """Get total number of memory nodes."""
        cursor = await self._conn.execute("SELECT COUNT(*) FROM memory_nodes")
        row = await cursor.fetchone()
        return row[0] if row else 0
    
    async def count_unanchored_nodes(self) -> int:
        """Get number of nodes without anchors."""
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM memory_nodes WHERE anchor_id IS NULL"
        )
        row = await cursor.fetchone()
        return row[0] if row else 0
    
    # ==================== Memory Edge Operations ====================
    
    async def save_memory_edge(self, edge: MemoryEdge) -> None:
        """Save a memory edge to the database."""
        await self._conn.execute("""
            INSERT OR REPLACE INTO memory_edges 
            (id, source, target, edge_type, transition_id, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            edge.id,
            edge.source,
            edge.target,
            edge.edge_type.value,
            edge.transition_id,
            edge.created_at,
            json.dumps(edge.metadata),
        ))
        await self._conn.commit()
    
    async def get_memory_edge(self, edge_id: str) -> Optional[MemoryEdge]:
        """Get a memory edge by ID."""
        cursor = await self._conn.execute(
            "SELECT * FROM memory_edges WHERE id = ?",
            (edge_id,)
        )
        row = await cursor.fetchone()
        
        if row is None:
            return None
        
        return MemoryEdge(
            id=row["id"],
            source=row["source"],
            target=row["target"],
            edge_type=row["edge_type"],
            transition_id=row["transition_id"],
            created_at=row["created_at"],
            metadata=json.loads(row["metadata"] or "{}"),
        )
    
    async def get_edges_by_source(self, source: str) -> List[MemoryEdge]:
        """Get all edges from a source node."""
        cursor = await self._conn.execute(
            "SELECT * FROM memory_edges WHERE source = ?",
            (source,)
        )
        rows = await cursor.fetchall()
        
        return [
            MemoryEdge(
                id=row["id"],
                source=row["source"],
                target=row["target"],
                edge_type=row["edge_type"],
                transition_id=row["transition_id"],
                created_at=row["created_at"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    async def get_edges_by_target(self, target: str) -> List[MemoryEdge]:
        """Get all edges pointing to a target node."""
        cursor = await self._conn.execute(
            "SELECT * FROM memory_edges WHERE target = ?",
            (target,)
        )
        rows = await cursor.fetchall()
        
        return [
            MemoryEdge(
                id=row["id"],
                source=row["source"],
                target=row["target"],
                edge_type=row["edge_type"],
                transition_id=row["transition_id"],
                created_at=row["created_at"],
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]
    
    # ==================== Anchor Operations ====================
    
    async def save_anchor_record(self, anchor: AnchorResult) -> None:
        """Save an anchor record to the database."""
        await self._conn.execute("""
            INSERT OR REPLACE INTO anchor_records 
            (anchor_id, backend, merkle_root, tx_id, timestamp, 
             block_height, verified, proof_data, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            anchor.anchor_id,
            anchor.backend.value,
            anchor.merkle_root,
            anchor.tx_id,
            anchor.timestamp,
            anchor.block_height,
            1 if anchor.verified else 0,
            json.dumps(anchor.proof_data),
            anchor.error,
        ))
        await self._conn.commit()
    
    async def get_anchor_record(self, anchor_id: str) -> Optional[AnchorResult]:
        """Get an anchor record by ID."""
        cursor = await self._conn.execute(
            "SELECT * FROM anchor_records WHERE anchor_id = ?",
            (anchor_id,)
        )
        row = await cursor.fetchone()
        
        if row is None:
            return None
        
        return AnchorResult(
            anchor_id=row["anchor_id"],
            backend=row["backend"],
            merkle_root=row["merkle_root"],
            tx_id=row["tx_id"],
            timestamp=row["timestamp"],
            block_height=row["block_height"],
            verified=bool(row["verified"]),
            proof_data=json.loads(row["proof_data"] or "{}"),
            error=row["error"],
        )
    
    async def get_anchors_by_root(self, merkle_root: str) -> List[AnchorResult]:
        """Get all anchors for a Merkle root."""
        cursor = await self._conn.execute(
            "SELECT * FROM anchor_records WHERE merkle_root = ?",
            (merkle_root,)
        )
        rows = await cursor.fetchall()
        
        return [
            AnchorResult(
                anchor_id=row["anchor_id"],
                backend=row["backend"],
                merkle_root=row["merkle_root"],
                tx_id=row["tx_id"],
                timestamp=row["timestamp"],
                block_height=row["block_height"],
                verified=bool(row["verified"]),
                proof_data=json.loads(row["proof_data"] or "{}"),
                error=row["error"],
            )
            for row in rows
        ]
    
    # ==================== State Snapshot Operations ====================
    
    async def save_state_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """Save a state snapshot to the database."""
        await self._conn.execute("""
            INSERT OR REPLACE INTO state_snapshots 
            (snapshot_id, timestamp, state_root, previous_snapshot_id, 
             memory_files, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            snapshot["snapshot_id"],
            snapshot["timestamp"],
            snapshot["state_root"],
            snapshot.get("previous_snapshot_id"),
            json.dumps(snapshot.get("memory_files", [])),
            json.dumps(snapshot.get("metadata", {})),
        ))
        await self._conn.commit()
    
    async def get_latest_snapshot(self) -> Optional[Dict[str, Any]]:
        """Get the latest state snapshot."""
        cursor = await self._conn.execute("""
            SELECT * FROM state_snapshots 
            ORDER BY timestamp DESC 
            LIMIT 1
        """)
        row = await cursor.fetchone()
        
        if row is None:
            return None
        
        return {
            "snapshot_id": row["snapshot_id"],
            "timestamp": row["timestamp"],
            "state_root": row["state_root"],
            "previous_snapshot_id": row["previous_snapshot_id"],
            "memory_files": json.loads(row["memory_files"] or "[]"),
            "metadata": json.loads(row["metadata"] or "{}"),
        }
    
    # ==================== Statistics ====================
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        cursor = await self._conn.execute("""
            SELECT 
                (SELECT COUNT(*) FROM transitions) as transitions,
                (SELECT COUNT(*) FROM memory_nodes) as nodes,
                (SELECT COUNT(*) FROM memory_edges) as edges,
                (SELECT COUNT(*) FROM anchor_records) as anchors,
                (SELECT COUNT(*) FROM memory_nodes WHERE anchor_id IS NULL) as unanchored,
                (SELECT state_root FROM state_snapshots ORDER BY timestamp DESC LIMIT 1) as latest_state_root
        """)
        row = await cursor.fetchone()
        
        return {
            "transitions": row["transitions"] if row else 0,
            "memory_nodes": row["nodes"] if row else 0,
            "memory_edges": row["edges"] if row else 0,
            "anchors": row["anchors"] if row else 0,
            "unanchored_nodes": row["unanchored"] if row else 0,
            "latest_state_root": row["latest_state_root"] if row else None,
        }


# Global store instance
_store: Optional[SQLiteStore] = None


async def get_store(db_path: Optional[str] = None) -> SQLiteStore:
    """
    Get the global SQLite store instance.
    
    Args:
        db_path: Optional custom database path
    
    Returns:
        SQLiteStore instance
    """
    global _store
    
    if _store is None:
        if db_path is None:
            from ..config import get_config
            config = get_config()
            db_path = config.database.path
        
        _store = SQLiteStore(db_path)
        await _store.connect()
    
    return _store


async def close_store() -> None:
    """Close the global store."""
    global _store
    
    if _store:
        await _store.close()
        _store = None
