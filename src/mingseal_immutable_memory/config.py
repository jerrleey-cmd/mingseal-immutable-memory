"""
Configuration management for MingSeal Immutable Memory.

Handles data directory resolution, anchoring backend selection,
and cryptographic key storage paths.
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AnchorBackendType(Enum):
    """Supported anchoring backend types."""
    LOCAL = "local"
    OTS = "ots"
    BSV = "bsv"


@dataclass
class AnchoringConfig:
    """Configuration for the anchoring backend."""
    backend: AnchorBackendType = AnchorBackendType.LOCAL
    # BSV-specific settings
    bsv_private_key_hex: Optional[str] = None  # HEX format private key
    bsv_network: str = "main"  # "main" or "test"
    bsv_fee_satoshis: int = 1000
    # OTS-specific settings
    ots_calendar_urls: list[str] = field(default_factory=lambda: [
        "https://www.ots.cdf.ericsson.net"
    ])


@dataclass
class DatabaseConfig:
    """Configuration for SQLite database."""
    path: str = ""  # Empty means default
    fts_enabled: bool = True


@dataclass
class StorageConfig:
    """Configuration for file-based storage."""
    base_path: str = ""  # Empty means default
    encryption_enabled: bool = False
    encryption_key_path: Optional[str] = None


@dataclass
class Config:
    """Main configuration class."""
    anchoring: AnchoringConfig = field(default_factory=AnchoringConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    
    @classmethod
    def _get_default_data_dir(cls) -> Path:
        """Determine default data directory based on environment."""
        # Check for explicit override
        if os.environ.get("MINGSEAL_DATA_DIR"):
            return Path(os.environ["MINGSEAL_DATA_DIR"])
        
        # Cloud computer: persist on /app/data
        if os.path.exists("/app/data"):
            base = Path("/app/data/mingseal-memory")
        else:
            base = Path.home() / ".mingseal" / "data"
        
        base.mkdir(parents=True, exist_ok=True)
        return base
    
    def resolve_paths(self) -> "Config":
        """Resolve all paths to absolute paths."""
        data_dir = self._get_default_data_dir()
        
        # Database path
        if not self.database.path:
            self.database.path = str(data_dir / "mingseal.db")
        
        # Storage base path
        if not self.storage.base_path:
            self.storage.base_path = str(data_dir)
        
        return self


class ConfigManager:
    """Manages configuration loading and persistence."""
    
    DEFAULT_CONFIG_NAME = "config.json"
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = self._get_default_config_dir()
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._config: Optional[Config] = None
    
    def _get_default_config_dir(self) -> Path:
        """Get default configuration directory."""
        if os.environ.get("MINGSEAL_CONFIG_DIR"):
            return Path(os.environ["MINGSEAL_CONFIG_DIR"])
        
        data_dir = Config._get_default_data_dir()
        return data_dir.parent / "config"
    
    @property
    def config(self) -> Config:
        """Get current configuration, loading from disk if needed."""
        if self._config is None:
            self._config = self.load()
        return self._config
    
    def load(self) -> Config:
        """Load configuration from disk."""
        config_path = self.config_dir / self.DEFAULT_CONFIG_NAME
        
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    data = json.load(f)
                
                anchoring_data = data.get("anchoring", {})
                anchoring = AnchoringConfig(
                    backend=AnchorBackendType(anchoring_data.get("backend", "local")),
                    bsv_private_key_hex=anchoring_data.get("bsv_private_key_hex"),
                    bsv_network=anchoring_data.get("bsv_network", "main"),
                    bsv_fee_satoshis=anchoring_data.get("bsv_fee_satoshis", 1000),
                    ots_calendar_urls=anchoring_data.get(
                        "ots_calendar_urls",
                        ["https://www.ots.cdf.ericsson.net"]
                    ),
                )
                
                database = DatabaseConfig(
                    path=data.get("database", {}).get("path", ""),
                    fts_enabled=data.get("database", {}).get("fts_enabled", True),
                )
                
                storage = StorageConfig(
                    base_path=data.get("storage", {}).get("base_path", ""),
                    encryption_enabled=data.get("storage", {}).get("encryption_enabled", False),
                )
                
                self._config = Config(
                    anchoring=anchoring,
                    database=database,
                    storage=storage,
                )
                self._config.resolve_paths()
                logger.info(f"Loaded configuration from {config_path}")
                return self._config
                
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        # Return default config
        self._config = Config()
        self._config.resolve_paths()
        return self._config
    
    def save(self, config: Optional[Config] = None) -> None:
        """Save configuration to disk."""
        if config is None:
            config = self._config
        if config is None:
            config = self.load()
        
        config_path = self.config_dir / self.DEFAULT_CONFIG_NAME
        
        data = {
            "anchoring": {
                "backend": config.anchoring.backend.value,
                "bsv_private_key_hex": config.anchoring.bsv_private_key_hex,
                "bsv_network": config.anchoring.bsv_network,
                "bsv_fee_satoshis": config.anchoring.bsv_fee_satoshis,
                "ots_calendar_urls": config.anchoring.ots_calendar_urls,
            },
            "database": {
                "path": config.database.path,
                "fts_enabled": config.database.fts_enabled,
            },
            "storage": {
                "base_path": config.storage.base_path,
                "encryption_enabled": config.storage.encryption_enabled,
                "encryption_key_path": config.storage.encryption_key_path,
            },
        }
        
        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved configuration to {config_path}")
    
    def update_anchoring_backend(self, backend: AnchorBackendType) -> Config:
        """Update the anchoring backend type."""
        self.config.anchoring.backend = backend
        self.save()
        return self.config


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_config() -> Config:
    """Get the current configuration."""
    return get_config_manager().config
