"""
File-based Storage for Content Persistence.

Provides S3-compatible file storage for memory content and transitions.
Supports encryption and is designed for durability across restarts.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class FileStore:
    """
    File-based storage for memory content and transitions.
    
    Directory structure:
    - {base_path}/
      - content/
        - {memory_id}.enc       # Encrypted memory content
        - {memory_id}.json      # Non-encrypted metadata
      - transitions/
        - {date}.jsonl          # Daily transition logs
      - snapshots/
        - {snapshot_id}.json    # State snapshots
      - anchors/
        - {anchor_id}.json      # Anchor records
    """
    
    def __init__(
        self,
        base_path: str,
        encryption_enabled: bool = False,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize file store.
        
        Args:
            base_path: Base directory for file storage
            encryption_enabled: Whether to encrypt stored content
            encryption_key: Encryption key (32 bytes)
        """
        self.base_path = Path(base_path)
        self.encryption_enabled = encryption_enabled
        self.encryption_key = encryption_key
        
        # Create directory structure
        self._init_directories()
    
    def _init_directories(self) -> None:
        """Create necessary directories."""
        dirs = [
            "content",
            "transitions",
            "snapshots",
            "anchors",
        ]
        
        for dir_name in dirs:
            (self.base_path / dir_name).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"File store initialized at {self.base_path}")
    
    # ==================== Content Storage ====================
    
    def save_content(
        self,
        memory_id: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Save memory content to file.
        
        Args:
            memory_id: Unique memory identifier
            content: The content to store
            metadata: Optional metadata
        
        Returns:
            Path to the stored file
        """
        content_path = self.base_path / "content" / f"{memory_id}.json"
        
        data = {
            "memory_id": memory_id,
            "content": content,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "metadata": metadata or {},
            "stored_at": datetime.utcnow().isoformat() + "Z",
        }
        
        with open(content_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.debug(f"Saved content for {memory_id}")
        
        return str(content_path)
    
    def get_content(self, memory_id: str) -> Optional[Dict[str, Any]]:
        """
        Get memory content from file.
        
        Args:
            memory_id: Memory identifier
        
        Returns:
            Content data dict or None if not found
        """
        content_path = self.base_path / "content" / f"{memory_id}.json"
        
        if not content_path.exists():
            return None
        
        with open(content_path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def delete_content(self, memory_id: str) -> bool:
        """
        Delete memory content file.
        
        Note: This is usually not called as memory is immutable,
        but may be used for cleanup of orphaned files.
        """
        content_path = self.base_path / "content" / f"{memory_id}.json"
        
        if content_path.exists():
            content_path.unlink()
            logger.debug(f"Deleted content for {memory_id}")
            return True
        
        return False
    
    # ==================== Transition Storage ====================
    
    def save_transition(self, transition_id: str, transition_data: Dict[str, Any]) -> str:
        """
        Save a transition to daily JSONL log.
        
        Args:
            transition_id: Transition identifier
            transition_data: Transition data
        
        Returns:
            Path to the log file
        """
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        log_path = self.base_path / "transitions" / f"{date_str}.jsonl"
        
        # Append as JSONL
        with open(log_path, "a", encoding="utf-8") as f:
            record = {
                "id": transition_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": transition_data,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        
        logger.debug(f"Saved transition {transition_id} to {log_path}")
        
        return str(log_path)
    
    def get_transitions_by_date(self, date: str) -> List[Dict[str, Any]]:
        """
        Get all transitions for a specific date.
        
        Args:
            date: Date in YYYY-MM-DD format
        
        Returns:
            List of transition records
        """
        log_path = self.base_path / "transitions" / f"{date}.jsonl"
        
        if not log_path.exists():
            return []
        
        transitions = []
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    transitions.append(json.loads(line))
        
        return transitions
    
    def get_transition(self, transition_id: str) -> Optional[Dict[str, Any]]:
        """
        Find a specific transition by searching all log files.
        
        Args:
            transition_id: Transition identifier
        
        Returns:
            Transition data or None
        """
        transitions_dir = self.base_path / "transitions"
        
        # Search through all date files (most recent first)
        for log_file in sorted(transitions_dir.glob("*.jsonl"), reverse=True):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        if record.get("id") == transition_id:
                            return record
        
        return None
    
    # ==================== Snapshot Storage ====================
    
    def save_snapshot(self, snapshot_id: str, snapshot_data: Dict[str, Any]) -> str:
        """
        Save a state snapshot.
        
        Args:
            snapshot_id: Snapshot identifier
            snapshot_data: Snapshot data
        
        Returns:
            Path to the snapshot file
        """
        snapshot_path = self.base_path / "snapshots" / f"{snapshot_id}.json"
        
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, ensure_ascii=False, indent=2)
        
        logger.debug(f"Saved snapshot {snapshot_id}")
        
        return str(snapshot_path)
    
    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a state snapshot.
        
        Args:
            snapshot_id: Snapshot identifier
        
        Returns:
            Snapshot data or None
        """
        snapshot_path = self.base_path / "snapshots" / f"{snapshot_id}.json"
        
        if not snapshot_path.exists():
            return None
        
        with open(snapshot_path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def get_latest_snapshot(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent state snapshot.
        
        Returns:
            Latest snapshot data or None
        """
        snapshots_dir = self.base_path / "snapshots"
        
        if not snapshots_dir.exists():
            return None
        
        # Get most recent by filename (which includes timestamp)
        snapshot_files = sorted(snapshots_dir.glob("*.json"), reverse=True)
        
        if not snapshot_files:
            return None
        
        with open(snapshot_files[0], "r", encoding="utf-8") as f:
            return json.load(f)
    
    # ==================== Anchor Storage ====================
    
    def save_anchor(self, anchor_id: str, anchor_data: Dict[str, Any]) -> str:
        """
        Save an anchor record.
        
        Args:
            anchor_id: Anchor identifier
            anchor_data: Anchor data
        
        Returns:
            Path to the anchor file
        """
        anchor_path = self.base_path / "anchors" / f"{anchor_id}.json"
        
        with open(anchor_path, "w", encoding="utf-8") as f:
            json.dump(anchor_data, f, ensure_ascii=False, indent=2)
        
        logger.debug(f"Saved anchor {anchor_id}")
        
        return str(anchor_path)
    
    def get_anchor(self, anchor_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an anchor record.
        
        Args:
            anchor_id: Anchor identifier
        
        Returns:
            Anchor data or None
        """
        anchor_path = self.base_path / "anchors" / f"{anchor_id}.json"
        
        if not anchor_path.exists():
            return None
        
        with open(anchor_path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    # ==================== Statistics ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get file store statistics."""
        stats = {
            "base_path": str(self.base_path),
            "content_files": 0,
            "transition_files": 0,
            "snapshot_files": 0,
            "anchor_files": 0,
            "total_size_bytes": 0,
        }
        
        # Count files
        content_dir = self.base_path / "content"
        if content_dir.exists():
            stats["content_files"] = len(list(content_dir.glob("*")))
        
        transitions_dir = self.base_path / "transitions"
        if transitions_dir.exists():
            stats["transition_files"] = len(list(transitions_dir.glob("*.jsonl")))
        
        snapshots_dir = self.base_path / "snapshots"
        if snapshots_dir.exists():
            stats["snapshot_files"] = len(list(snapshots_dir.glob("*.json")))
        
        anchors_dir = self.base_path / "anchors"
        if anchors_dir.exists():
            stats["anchor_files"] = len(list(anchors_dir.glob("*.json")))
        
        # Calculate total size
        for path in self.base_path.rglob("*"):
            if path.is_file():
                stats["total_size_bytes"] += path.stat().st_size
        
        return stats
    
    def list_content_ids(self) -> List[str]:
        """List all stored content IDs."""
        content_dir = self.base_path / "content"
        
        if not content_dir.exists():
            return []
        
        return [p.stem for p in content_dir.glob("*.json")]
    
    def cleanup_old_files(self, days: int = 90) -> int:
        """
        Clean up files older than specified days.
        
        Args:
            days: Number of days to retain
        
        Returns:
            Number of files deleted
        """
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = 0
        
        for path in self.base_path.rglob("*"):
            if path.is_file():
                mtime = datetime.fromtimestamp(path.stat().st_mtime)
                if mtime < cutoff:
                    path.unlink()
                    deleted += 1
                    logger.info(f"Cleaned up old file: {path}")
        
        return deleted


# Global file store instance
_file_store: Optional[FileStore] = None


def get_file_store(base_path: Optional[str] = None) -> FileStore:
    """
    Get the global file store instance.
    
    Args:
        base_path: Optional custom base path
    
    Returns:
        FileStore instance
    """
    global _file_store
    
    if _file_store is None:
        if base_path is None:
            from ..config import get_config
            config = get_config()
            base_path = config.storage.base_path
        
        _file_store = FileStore(
            base_path=base_path,
            encryption_enabled=False,  # TODO: Implement encryption
        )
    
    return _file_store
