# MingSeal Immutable Memory

[![PyPI version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/mingchain/mingseal-immutable-memory)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)

> **Memory is not cache — it's a ledger.** An agent should never "recall" something it cannot prove it once knew.

An immutable memory system for AI agents, based on [Craig Wright's paper](https://arxiv.org/abs/2506.13246) on blockchain-indexed automata-theoretic frameworks. Works with any MCP-compatible agent (Hermes, OpenClaw, Claude Code, etc.) out of the box.

**Zero barrier to start**: No blockchain assets needed. Use for free with local signing. Upgrade to blockchain anchoring when you need third-party verifiable proof.

## Overview

This project provides a Model Context Protocol (MCP) server that implements an immutable memory anchoring system for AI agents. It features:

- **Layer 1**: State transition capture and recording
- **Layer 2**: DAG-based knowledge graph (append-only with cycle detection)
- **Layer 3**: Merkle tree construction and proof generation
- **Layer 4**: Pluggable anchoring (Local Sign / OpenTimestamps / BSV)
- **Layer 5**: Verification engine (integrity + hallucination detection)
- **Layer 6**: Cognitive state root computation

## Key Features

- **Zero门槛启动**: No blockchain assets required to use basic functionality
- **MCP Protocol**: Language-agnostic, any MCP client can connect
- **Pluggable Anchoring**: Three levels of anchoring to choose from
  - Level 0: Local HMAC-SHA256 signing (free, local only)
  - Level 1: OpenTimestamps (free, BTC-verifiable)
  - Level 2: BSV OP_RETURN (paid, full legal attestation)
- **DAG Knowledge Graph**: Append-only memory with derivation tracking
- **Merkle Proofs**: Efficient verification of memory inclusion
- **FTS5 Search**: Full-text search across all memories

## Installation

```bash
# Clone the repository
git clone https://github.com/mingchain/mingseal-immutable-memory.git
cd mingseal-immutable-memory

# Install in development mode
pip install -e .

# Or install dependencies only
pip install -e ".[dev]"
```

## Quick Start

### Start the MCP Server

```bash
# Start with default configuration (Local signing)
python -m mingseal_immutable_memory.server

# Or use the command-line entry point
mingseal-memory
```

## MCP Tools

The server provides 7 tools:

| Tool | Description |
|------|-------------|
| `memory_capture_transition` | Capture a cognitive state transition |
| `memory_store` | Store a new memory in the DAG |
| `memory_recall` | Recall memories using full-text search |
| `memory_verify` | Verify a memory node's integrity |
| `memory_trace` | Trace derivation chain of a memory |
| `memory_anchor` | Manually trigger Merkle anchoring |
| `memory_status` | Get memory system status |

## Integration

### Hermes Agent

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  mingseal-memory:
    command: python3
    args:
      - "-m"
      - "mingseal_immutable_memory.server"
    env:
      MINGSEAL_DATA_DIR: "~/.mingseal/data"
      MINGSEAL_ANCHOR_BACKEND: "local"  # or "ots" or "bsv"
```

### Claude Code / Cursor / VS Code

Add to your MCP client settings:

```json
{
  "mcpServers": {
    "mingseal-memory": {
      "command": "python3",
      "args": ["-m", "mingseal_immutable_memory.server"],
      "env": {
        "MINGSEAL_DATA_DIR": "~/.mingseal/data",
        "MINGSEAL_ANCHOR_BACKEND": "local"
      }
    }
  }
}
```

### OpenClaw

Connect via MCP protocol using supergateway or the built-in MCP client support.

## How It Works

```
Agent Event → Capture Transition → Store in DAG → Build Merkle Tree → Anchor
                    ↓                    ↓              ↓              ↓
              (state_hash)      (parent edges)    (inclusion proof)  (backend)
                                                                  ┌─────────────┐
                                                                  │ Local (free) │
                                                                  │ OTS  (free)  │
                                                                  │ BSV  (paid)  │
                                                                  └─────────────┘
```

When an agent produces an output, the system:
1. Captures the cognitive state transition (input → output, with state hash)
2. Stores the memory in an append-only DAG with derivation edges
3. Periodically batches transitions into a Merkle tree
4. Anchors the Merkle root via the configured backend
5. Any memory can be verified: content hash → Merkle proof → anchor

## Configuration

Configuration is stored in `~/.mingseal/config/config.json`:

```json
{
  "anchoring": {
    "backend": "local",
    "bsv_wif_key": null,
    "bsv_network": "main"
  },
  "database": {
    "path": "",
    "fts_enabled": true
  },
  "storage": {
    "base_path": "",
    "encryption_enabled": false
  }
}
```

### Environment Variables

- `MINGSEAL_DATA_DIR`: Override data directory
- `MINGSEAL_CONFIG_DIR`: Override config directory

## Architecture

```
mingseal-immutable-memory/
├── src/mingseal_immutable_memory/
│   ├── server.py              # MCP Server entry point
│   ├── config.py              # Configuration management
│   ├── core/
│   │   ├── transition.py      # Layer 1: State transitions
│   │   ├── dag.py             # Layer 2: Knowledge graph
│   │   ├── merkle.py          # Layer 3: Merkle trees
│   │   ├── anchor.py          # Layer 4: Anchoring backends
│   │   ├── verification.py    # Layer 5: Verification engine
│   │   └── state_root.py     # Layer 6: State root computation
│   ├── store/
│   │   ├── sqlite_store.py    # SQLite with FTS5
│   │   └── file_store.py      # File persistence
│   ├── crypto/
│   │   ├── signing.py         # Local signing
│   │   └── ecdh.py            # ECDH key exchange
│   └── models/
│       ├── transition.py      # Transition model
│       ├── memory_node.py     # Memory node model
│       └── anchor_result.py   # Anchor result model
└── tests/                     # Unit tests
```

## Data Models

### Transition

Represents a cognitive state transition:

```python
{
    "id": "sha256_hash",
    "from_state": "previous_state_hash",
    "input_type": "user_msg",
    "input_hash": "sha256_hash",
    "output_type": "reply",
    "output_hash": "sha256_hash",
    "to_state": "new_state_hash",
    "timestamp": "2024-01-01T00:00:00Z",
    "signature": "optional_signature",
    "metadata": {}
}
```

### MemoryNode

Represents a memory entry in the DAG:

```python
{
    "id": "mem_sha256_hash",
    "content_hash": "sha256_hash",
    "parents": ["parent_node_ids"],
    "transition_id": "transition_id",
    "merkle_root": "root_hash",
    "merkle_proof": {"root": "", "path": [], "indices": []},
    "anchor_id": "anchor_id",
    "access_level": 0,
    "created_at": "2024-01-01T00:00:00Z",
    "scope": "/knowledge/topic"
}
```

## Anchoring Backends

### Level 0: Local Sign

- Free, no network required
- Creates HMAC-SHA256 commitment
- Can verify integrity locally
- Not third-party verifiable

### Level 1: OpenTimestamps

- Free, uses public OTS calendars
- Timestamps anchored to Bitcoin
- Third-party verifiable
- Average confirmation: hours to days

### Level 2: BSV OP_RETURN

- Paid (BSV transaction fees)
- Direct blockchain anchoring
- Full legal attestation capability
- Format: `MSLL | v2 | root(32B) | epoch | agent_pk_hash | signature`

## Roadmap

- [x] Core memory engine (Transition + DAG + Merkle)
- [x] MCP Server with 7 tools
- [x] Local signing anchor (free, zero-config)
- [x] OpenTimestamps anchor (free, BTC-verifiable)
- [x] BSV OP_RETURN anchor interface (paid, full attestation)
- [x] FTS5 full-text search
- [x] ECDH access control preparation
- [ ] Real BSV transaction integration (current: simulated)
- [ ] Real OpenTimestamps integration (current: simulated)
- [ ] Semantic vector search (embeddings-based recall)
- [ ] Memory consolidation (LLM-driven merge of similar memories)
- [ ] Multi-agent shared memory pools
- [ ] ZKP inclusion proofs
- [ ] Key rotation chains
- [ ] PyPI package publication

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mingseal_immutable_memory

# Run specific test file
pytest tests/test_dag.py
```

### Code Style

```bash
# Format code
black src/

# Lint code
ruff check src/
```

## Dependencies

- `mcp>=1.0.0` - MCP SDK
- `pydantic>=2.0` - Data models
- `cryptography>=42.0` - Cryptographic operations
- `aiosqlite>=0.20` - Async SQLite

## License

MIT License

## References

- Craig Wright, "On Immutable Memory Systems for Artificial Agents", arXiv:2506.13246
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Hermes Agent](https://github.com/NousResearch/hermes-agent)
- [OpenTimestamps](https://opentimestamps.org/)
- BSV Blockchain — for scalable on-chain data anchoring
