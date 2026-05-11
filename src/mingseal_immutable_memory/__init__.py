"""
MingSeal Immutable Memory - MCP Server for AI Agent Memory Anchoring

This module provides an immutable memory system for AI agents, implementing
the architecture described in Craig Wright's paper "On Immutable Memory 
Systems for Artificial Agents" (arXiv:2506.13246).

Key Features:
- Layer 1: State transition capture and recording
- Layer 2: DAG-based knowledge graph (append-only with cycle detection)
- Layer 3: Merkle tree construction and proof generation
- Layer 4: Pluggable anchoring (Local Sign / OpenTimestamps / BSV)
- Layer 5: Verification engine (integrity + hallucination detection)
- Layer 6: Cognitive state root computation

License: MIT
Author: MingChain
"""

__version__ = "0.1.0"
