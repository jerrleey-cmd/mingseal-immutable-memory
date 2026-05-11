"""
MingSeal Immutable Memory - MCP Server Implementation.

This module implements the MCP (Model Context Protocol) server that
provides memory anchoring tools to AI agents. It integrates all core
modules into a unified interface accessible via MCP protocol.
"""

import asyncio
import logging
import sys
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
    ListToolsResult,
)

from .config import get_config, ConfigManager, AnchorBackendType
from .models.transition import Transition, create_transition
from .models.memory_node import MemoryNode, create_memory_node, EdgeType
from .models.anchor_result import AnchorResult, AnchorBackend, create_anchor_result
from .core import (
    TransitionStore,
    MemoryDAG,
    MerkleTree,
    LocalSignAnchor,
    OpenTimestampsAnchor,
    BSVAnchor,
    VerificationEngine,
    compute_state_root,
    StateSnapshot,
    create_state_snapshot,
)
from .store import SQLiteStore, get_store, FileStore, get_file_store
from .crypto import LocalSigner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Server instance
APP_NAME = "mingseal-immutable-memory"
APP_VERSION = "0.1.0"


class MemoryServer:
    """
    Main memory server coordinating all components.
    
    This class manages:
    - In-memory state (TransitionStore, MemoryDAG)
    - Persistence (SQLiteStore, FileStore)
    - Anchoring (configurable backend)
    - Verification engine
    """
    
    def __init__(self):
        """Initialize the memory server."""
        self._transition_store: Optional[TransitionStore] = None
        self._dag: Optional[MemoryDAG] = None
        self._store: Optional[SQLiteStore] = None
        self._file_store: Optional[FileStore] = None
        self._anchor: Optional[LocalSignAnchor] = None
        self._verification: Optional[VerificationEngine] = None
        self._signer: Optional[LocalSigner] = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize all components."""
        if self._initialized:
            return
        
        logger.info("Initializing MingSeal Immutable Memory Server...")
        
        # Load configuration
        config = get_config()
        
        # Initialize stores
        self._store = await get_store(config.database.path)
        self._file_store = get_file_store(config.storage.base_path)
        
        # Initialize in-memory structures
        self._transition_store = TransitionStore()
        self._dag = MemoryDAG()
        
        # Initialize signer
        self._signer = LocalSigner()
        
        # Initialize anchor backend
        backend_type = config.anchoring.backend
        if backend_type == AnchorBackendType.LOCAL:
            self._anchor = LocalSignAnchor()
        elif backend_type == AnchorBackendType.OTS:
            self._anchor = OpenTimestampsAnchor(config.anchoring.ots_calendar_urls)
        elif backend_type == AnchorBackendType.BSV:
            bsv_key = config.anchoring.bsv_private_key_hex or os.environ.get("MINGSEAL_BSV_PRIVATE_KEY")
            self._anchor = BSVAnchor(
                private_key_hex=bsv_key,
                network=config.anchoring.bsv_network,
                fee_satoshis=config.anchoring.bsv_fee_satoshis,
            )
        else:
            self._anchor = LocalSignAnchor()
        
        # Initialize verification engine
        self._verification = VerificationEngine()
        
        # Load existing data from database
        await self._load_from_db()
        
        self._initialized = True
        logger.info("MingSeal Immutable Memory Server initialized")
    
    async def _load_from_db(self) -> None:
        """Load existing data from database."""
        if not self._store:
            return
        
        # Load transitions
        transitions = await self._store.get_transitions_since(limit=10000)
        for t in transitions:
            self._transition_store.transitions[t.id] = t
            if t.to_state not in self._transition_store.state_chain:
                self._transition_store.state_chain.append(t.to_state)
        
        if self._transition_store.state_chain:
            self._transition_store.latest_state = self._transition_store.state_chain[-1]
        
        logger.info(f"Loaded {len(transitions)} transitions from database")
    
    async def shutdown(self) -> None:
        """Shutdown the server."""
        from .store import close_store
        await close_store()
        logger.info("MingSeal Immutable Memory Server shutdown")
    
    # ==================== MCP Tool Implementations ====================
    
    async def capture_transition(
        self,
        input_type: str,
        input_content: str,
        output_type: str,
        output_content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Capture a cognitive state transition.
        
        This is the core operation for recording agent cognition.
        """
        # Create transition
        transition = self._transition_store.capture(
            input_type=input_type,
            input_content=input_content,
            output_type=output_type,
            output_content=output_content,
            metadata=metadata,
        )
        
        # Persist to database
        if self._store:
            await self._store.save_transition(transition)
        
        # Also save to file log
        if self._file_store:
            self._file_store.save_transition(
                transition.id,
                transition.model_dump(),
            )
        
        return {
            "transition_id": transition.id,
            "from_state": transition.from_state,
            "to_state": transition.to_state,
            "timestamp": transition.timestamp,
            "input_hash": transition.input_hash,
            "output_hash": transition.output_hash,
        }
    
    async def store_memory(
        self,
        content: str,
        parents: Optional[List[str]] = None,
        scope: str = "/",
        access_level: int = 0,
    ) -> Dict[str, Any]:
        """
        Store a new memory in the DAG.
        
        Automatically creates edges to parent memories.
        """
        # Use latest transition as context
        latest_transition = self._transition_store.get_latest(1)
        transition_id = latest_transition[0].id if latest_transition else "genesis"
        
        # Create memory node
        node = self._dag.add_node(
            content=content,
            transition_id=transition_id,
            parents=parents,
            scope=scope,
            access_level=access_level,
        )
        
        # Persist node
        if self._store:
            await self._store.save_memory_node(node, content)
        
        # Also save to file store
        if self._file_store:
            self._file_store.save_content(node.id, content, node.metadata)
        
        return {
            "memory_node_id": node.id,
            "content_hash": node.content_hash,
            "scope": node.scope,
            "parents": node.parents,
            "created_at": node.created_at,
        }
    
    async def recall_memory(
        self,
        query: str,
        limit: int = 10,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Recall memories matching a query.
        
        Uses FTS5 full-text search when query is text.
        """
        results = []
        
        if self._store:
            # Use FTS search
            nodes = await self._store.search_memory(
                query=query,
                scope=scope,
                limit=limit,
            )
            
            for node in nodes:
                # Get full content
                content = await self._store.get_memory_content(node.id)
                
                results.append({
                    "node_id": node.id,
                    "content": content or node.metadata.get("content_preview", ""),
                    "content_hash": node.content_hash,
                    "scope": node.scope,
                    "created_at": node.created_at,
                    "merkle_proof": node.merkle_proof,
                    "anchor_id": node.anchor_id,
                })
        
        return {
            "query": query,
            "results": results,
            "count": len(results),
        }
    
    async def verify_memory(self, memory_id: str) -> Dict[str, Any]:
        """
        Verify a memory node's integrity.
        
        Checks content hash, Merkle proof, and anchor status.
        """
        # Get node
        node = self._dag.get_node(memory_id)
        if not node and self._store:
            node = await self._store.get_memory_node(memory_id)
        
        if not node:
            return {
                "verified": False,
                "error": f"Memory node {memory_id} not found",
            }
        
        # Get content for hash verification
        content = None
        if self._store:
            content = await self._store.get_memory_content(memory_id)
        
        # Run verification
        report = self._verification.verify_node_integrity(node, content)
        
        return {
            "node_id": node.id,
            "verified": report.status.value == "verified",
            "status": report.status.value,
            "content_hash_valid": report.content_hash_valid,
            "merkle_proof_valid": report.merkle_proof_valid,
            "anchor_confirmed": report.anchor_confirmed,
            "anchor_timestamp": report.anchor_timestamp,
            "warnings": report.warnings,
            "errors": report.errors,
        }
    
    async def trace_memory(self, memory_id: str, limit: int = 100) -> Dict[str, Any]:
        """
        Trace the derivation chain of a memory.
        
        Follows parent edges back to root nodes.
        """
        # Get starting node
        node = self._dag.get_node(memory_id)
        if not node and self._store:
            node = await self._store.get_memory_node(memory_id)
        
        if not node:
            return {
                "error": f"Memory node {memory_id} not found",
                "chain": [],
            }
        
        # Trace back through parents
        chain = self._dag.trace_back(memory_id, limit=limit)
        
        chain_data = []
        for n in chain:
            # Get content for each node
            content = None
            if self._store:
                content = await self._store.get_memory_content(n.id)
            
            chain_data.append({
                "node_id": n.id,
                "content": content or n.metadata.get("content_preview", ""),
                "content_hash": n.content_hash,
                "scope": n.scope,
                "created_at": n.created_at,
                "parents": n.parents,
            })
        
        return {
            "start_node_id": memory_id,
            "chain": chain_data,
            "depth": len(chain_data),
        }
    
    async def anchor_memories(self, force: bool = False) -> Dict[str, Any]:
        """
        Anchor unanchored memories using Merkle tree.
        
        Creates a batch from recent transitions and anchors the root.
        """
        if not self._transition_store or not self._anchor:
            return {"error": "Server not initialized"}
        
        # Get unanchored transitions
        unanchored = []
        for tid, t in self._transition_store.transitions.items():
            # Check if this transition has anchored nodes
            nodes = self._dag.get_by_transition(tid)
            if nodes and not any(n.anchor_id for n in nodes):
                unanchored.append(t)
        
        if not unanchored:
            return {
                "message": "No unanchored memories to anchor",
                "anchor_result": None,
            }
        
        # Build Merkle tree
        from .core.merkle import create_merkle_tree_from_transitions
        tree = create_merkle_tree_from_transitions(unanchored)
        
        if not tree.root:
            return {"error": "Failed to build Merkle tree"}
        
        # Anchor the root
        merkle_root_bytes = bytes.fromhex(tree.root)
        anchor_result = await self._anchor.anchor(merkle_root_bytes, {
            "transition_count": len(unanchored),
            "force": force,
        })
        
        # Update nodes with Merkle proofs
        if self._store:
            await self._store.save_anchor_record(anchor_result)
        
        node_ids = []
        for i, t in enumerate(unanchored):
            # Get nodes for this transition
            nodes = self._dag.get_by_transition(t.id)
            for node in nodes:
                # Update with anchor info
                node.merkle_root = tree.root
                proof = tree.get_proof(node.content_hash)
                if proof:
                    node.merkle_proof = proof.to_dict()
                node.anchor_id = anchor_result.anchor_id
                
                if self._store:
                    await self._store.save_memory_node(node)
                
                node_ids.append(node.id)
        
        return {
            "merkle_root": tree.root,
            "transitions_anchored": len(unanchored),
            "nodes_anchored": len(node_ids),
            "anchor_result": {
                "anchor_id": anchor_result.anchor_id,
                "backend": anchor_result.backend.value,
                "timestamp": anchor_result.timestamp,
                "tx_id": anchor_result.tx_id,
                "verified": anchor_result.verified,
            },
        }
    
    async def get_status(self) -> Dict[str, Any]:
        """Get the current status of the memory system."""
        stats = {}
        
        if self._store:
            db_stats = await self._store.get_stats()
            stats.update(db_stats)
        
        if self._file_store:
            file_stats = self._file_store.get_stats()
            stats["file_store"] = file_stats
        
        if self._transition_store:
            stats["transition_chain_length"] = len(self._transition_store.state_chain)
            stats["latest_state"] = self._transition_store.latest_state
        
        if self._dag:
            stats["dag_stats"] = self._dag.get_stats()
        
        if self._anchor:
            stats["anchor_capability"] = self._anchor.capability().model_dump()
        
        return stats


# Create server instance
memory_server = MemoryServer()
mcp_server = Server(APP_NAME)


@mcp_server.list_tools()
async def list_tools() -> ListToolsResult:
    """List all available MCP tools."""
    return ListToolsResult(
        tools=[
            Tool(
                name="memory_capture_transition",
                description="Capture a cognitive state transition in the agent's reasoning process. Records input/output pairs and computes new state.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "input_type": {
                            "type": "string",
                            "enum": ["user_msg", "tool_call", "timer", "memory_update"],
                            "description": "Type of input that triggered this transition",
                        },
                        "input_content": {
                            "type": "string",
                            "description": "The actual input content",
                        },
                        "output_type": {
                            "type": "string",
                            "enum": ["reply", "tool_result", "memory_write"],
                            "description": "Type of output produced",
                        },
                        "output_content": {
                            "type": "string",
                            "description": "The actual output content",
                        },
                        "metadata": {
                            "type": "object",
                            "description": "Additional metadata",
                        },
                    },
                    "required": ["input_type", "input_content", "output_type", "output_content"],
                },
            ),
            Tool(
                name="memory_store",
                description="Store a new memory in the DAG. Automatically creates edges to parent memories if specified.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "The memory content to store",
                        },
                        "parents": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Parent memory node IDs for derivation relationships",
                        },
                        "scope": {
                            "type": "string",
                            "description": "Hierarchical scope path for organization (e.g., /infrastructure/database)",
                            "default": "/",
                        },
                        "access_level": {
                            "type": "integer",
                            "description": "Access control level (0=public, 1=internal, 2=confidential)",
                            "default": 0,
                        },
                    },
                    "required": ["content"],
                },
            ),
            Tool(
                name="memory_recall",
                description="Recall memories matching a query using full-text search. Returns matching memories with Merkle proofs.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query for memory content",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                            "default": 10,
                        },
                        "scope": {
                            "type": "string",
                            "description": "Optional scope to filter results",
                        },
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="memory_verify",
                description="Verify a memory node's integrity. Checks content hash, Merkle proof, and anchor status.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "memory_id": {
                            "type": "string",
                            "description": "The memory node ID to verify",
                        },
                    },
                    "required": ["memory_id"],
                },
            ),
            Tool(
                name="memory_trace",
                description="Trace the derivation chain of a memory. Follows parent edges back to root nodes.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "memory_id": {
                            "type": "string",
                            "description": "The memory node ID to trace from",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum chain depth",
                            "default": 100,
                        },
                    },
                    "required": ["memory_id"],
                },
            ),
            Tool(
                name="memory_anchor",
                description="Manually trigger Merkle anchoring of unanchored memories. Creates a batch from recent transitions and anchors the root.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "force": {
                            "type": "boolean",
                            "description": "Force anchoring even if recent",
                            "default": False,
                        },
                    },
                },
            ),
            Tool(
                name="memory_status",
                description="Get the current status of the memory system including node counts, anchor status, and DAG statistics.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]
    )


@mcp_server.call_tool()
async def call_tool(
    name: str,
    arguments: Dict[str, Any],
) -> CallToolResult:
    """Handle tool calls from MCP clients."""
    # Ensure server is initialized
    if not memory_server._initialized:
        await memory_server.initialize()
    
    try:
        if name == "memory_capture_transition":
            result = await memory_server.capture_transition(
                input_type=arguments["input_type"],
                input_content=arguments["input_content"],
                output_type=arguments["output_type"],
                output_content=arguments["output_content"],
                metadata=arguments.get("metadata"),
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_store":
            result = await memory_server.store_memory(
                content=arguments["content"],
                parents=arguments.get("parents"),
                scope=arguments.get("scope", "/"),
                access_level=arguments.get("access_level", 0),
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_recall":
            result = await memory_server.recall_memory(
                query=arguments["query"],
                limit=arguments.get("limit", 10),
                scope=arguments.get("scope"),
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_verify":
            result = await memory_server.verify_memory(
                memory_id=arguments["memory_id"],
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_trace":
            result = await memory_server.trace_memory(
                memory_id=arguments["memory_id"],
                limit=arguments.get("limit", 100),
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_anchor":
            result = await memory_server.anchor_memories(
                force=arguments.get("force", False),
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        elif name == "memory_status":
            result = await memory_server.get_status()
            return CallToolResult(
                content=[TextContent(type="text", text=str(result))]
            )
        
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                isError=True,
            )
    
    except Exception as e:
        logger.error(f"Tool execution error: {e}", exc_info=True)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {str(e)}")],
            isError=True,
        )


async def main():
    """Main entry point for the MCP server."""
    # Initialize server
    await memory_server.initialize()
    
    # Run with stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
