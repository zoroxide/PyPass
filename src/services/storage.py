"""
Storage layer using SQLite3 for persisting password data.
Handles database operations for encrypted password vault.
"""

import sqlite3
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import json


class StorageService:
    """
    Manages persistent storage of encrypted password data using SQLite3.
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize storage service.
        
        Args:
            storage_path: Path to database file. If None, uses default location.
        """
        if storage_path:
            self._storage_path = Path(storage_path)
        else:
            # Always use user's AppData directory for vault
            # This ensures each user has their own vault, even with compiled exe
            app_dir = Path.home() / "AppData" / "Local" / "PyPass"
            app_dir.mkdir(parents=True, exist_ok=True)
            self._storage_path = app_dir / "vault.db"
        
        self._conn: Optional[sqlite3.Connection] = None
        self._initialize_database()
    
    @property
    def storage_path(self) -> Path:
        """Get the storage file path."""
        return self._storage_path
    
    def _initialize_database(self) -> None:
        """Initialize database schema if not exists."""
        self._conn = sqlite3.connect(str(self._storage_path))
        self._conn.row_factory = sqlite3.Row
        
        cursor = self._conn.cursor()
        
        # Create vault_config table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        
        # Create passwords table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL
            )
        """)
        
        # Create index for search optimization
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_title ON passwords(title)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_username ON passwords(username)
        """)
        
        self._conn.commit()
    
    def exists(self) -> bool:
        """
        Check if vault is initialized (has config data).
        
        Returns:
            True if vault exists, False otherwise.
        """
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vault_config WHERE key = 'salt'")
        count = cursor.fetchone()[0]
        return count > 0
    
    def save_config(self, salt: str, test_data: str) -> None:
        """
        Save vault configuration (salt and test data).
        
        Args:
            salt: Base64 encoded salt.
            test_data: Base64 encoded test data for password verification.
        """
        cursor = self._conn.cursor()
        
        # Insert or replace config
        cursor.execute("""
            INSERT OR REPLACE INTO vault_config (key, value) 
            VALUES ('salt', ?)
        """, (salt,))
        
        cursor.execute("""
            INSERT OR REPLACE INTO vault_config (key, value) 
            VALUES ('test_data', ?)
        """, (test_data,))
        
        # Save metadata
        cursor.execute("""
            INSERT OR REPLACE INTO vault_config (key, value) 
            VALUES ('version', '1.0')
        """)
        
        cursor.execute("""
            INSERT OR REPLACE INTO vault_config (key, value) 
            VALUES ('last_modified', ?)
        """, (datetime.now().isoformat(),))
        
        self._conn.commit()
    
    def load_config(self) -> Dict[str, str]:
        """
        Load vault configuration.
        
        Returns:
            Dictionary containing salt and test_data.
            
        Raises:
            ValueError: If vault not initialized.
        """
        if not self.exists():
            raise ValueError("Vault not initialized")
        
        cursor = self._conn.cursor()
        cursor.execute("SELECT key, value FROM vault_config WHERE key IN ('salt', 'test_data')")
        
        config = {}
        for row in cursor.fetchall():
            config[row['key']] = row['value']
        
        return config
    
    def save_entry(self, entry_data: Dict[str, Any]) -> None:
        """
        Save or update a password entry.
        
        Args:
            entry_data: Dictionary containing entry data.
        """
        cursor = self._conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO passwords 
            (id, title, username, password, url, notes, created_at, modified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry_data['id'],
            entry_data['title'],
            entry_data['username'],
            entry_data['password'],  # Already encrypted bytes
            entry_data.get('url', ''),
            entry_data.get('notes', ''),
            entry_data['created_at'],
            entry_data['modified_at']
        ))
        
        self._conn.commit()
    
    def load_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a specific password entry.
        
        Args:
            entry_id: ID of the entry to load.
            
        Returns:
            Dictionary containing entry data or None if not found.
        """
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE id = ?", (entry_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        return dict(row)
    
    def load_all_entries(self) -> List[Dict[str, Any]]:
        """
        Load all password entries.
        
        Returns:
            List of dictionaries containing entry data.
        """
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM passwords ORDER BY title COLLATE NOCASE")
        
        return [dict(row) for row in cursor.fetchall()]
    
    def delete_entry(self, entry_id: str) -> None:
        """
        Delete a password entry.
        
        Args:
            entry_id: ID of the entry to delete.
        """
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        self._conn.commit()
    
    def search_entries(self, query: str) -> List[Dict[str, Any]]:
        """
        Search password entries by title, username, or URL.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching entries.
        """
        cursor = self._conn.cursor()
        search_pattern = f"%{query}%"
        
        cursor.execute("""
            SELECT * FROM passwords 
            WHERE title LIKE ? OR username LIKE ? OR url LIKE ?
            ORDER BY title COLLATE NOCASE
        """, (search_pattern, search_pattern, search_pattern))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def delete_all(self) -> None:
        """Delete all data from the vault."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM passwords")
        cursor.execute("DELETE FROM vault_config")
        self._conn.commit()
    
    def backup(self, backup_path: str) -> None:
        """
        Create a backup of the database.
        
        Args:
            backup_path: Path where backup should be created.
        """
        # Close current connection
        if self._conn:
            self._conn.close()
        
        # Copy database file
        import shutil
        shutil.copy2(self._storage_path, backup_path)
        
        # Reconnect
        self._initialize_database()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get vault statistics.
        
        Returns:
            Dictionary with stats (entry count, creation date, etc.).
        """
        cursor = self._conn.cursor()
        
        # Get entry count
        cursor.execute("SELECT COUNT(*) as count FROM passwords")
        entry_count = cursor.fetchone()['count']
        
        # Get creation date
        cursor.execute("SELECT value FROM vault_config WHERE key = 'version'")
        version = cursor.fetchone()
        
        # Get last modified
        cursor.execute("SELECT value FROM vault_config WHERE key = 'last_modified'")
        last_modified = cursor.fetchone()
        
        return {
            'entry_count': entry_count,
            'version': version['value'] if version else 'Unknown',
            'last_modified': last_modified['value'] if last_modified else 'Unknown'
        }
    
    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __del__(self):
        """Cleanup database connection on object destruction."""
        self.close()
