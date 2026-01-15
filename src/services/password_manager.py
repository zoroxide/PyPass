"""
Business logic layer for password manager.
Orchestrates encryption, storage, and password operations.
"""

from typing import List, Dict, Optional
from datetime import datetime
import base64
from dataclasses import dataclass, asdict

from .encryption import EncryptionService
from .storage import StorageService
from .password_generator import PasswordGenerator


@dataclass
class PasswordEntry:
    """Represents a single password entry."""
    id: str
    title: str
    username: str
    password: str  # This will be encrypted
    url: str
    notes: str
    created_at: str
    modified_at: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict) -> 'PasswordEntry':
        """Create from dictionary."""
        return PasswordEntry(**data)


class PasswordManager:
    """
    Core business logic for password management.
    Handles CRUD operations, encryption, and storage.
    """
    
    def __init__(self, storage_service: StorageService, encryption_service: EncryptionService):
        """
        Initialize password manager.
        
        Args:
            storage_service: Service for data persistence.
            encryption_service: Service for encryption/decryption.
        """
        self._storage = storage_service
        self._encryption = encryption_service
        self._entries: Dict[str, PasswordEntry] = {}
        self._is_unlocked = False
    
    @property
    def is_unlocked(self) -> bool:
        """Check if vault is unlocked."""
        return self._is_unlocked
    
    def create_vault(self, master_password: str) -> None:
        """
        Create a new password vault.
        
        Args:
            master_password: Master password for the vault.
            
        Raises:
            ValueError: If vault already exists.
        """
        if self._storage.exists():
            raise ValueError("Vault already exists")
        
        # Initialize encryption with master password
        self._encryption.initialize_with_password(master_password)
        
        # Create test data to verify password later
        test_data = self._encryption.encrypt("vault_initialized")
        
        # Save config to database
        salt_b64 = base64.b64encode(self._encryption.salt).decode()
        test_data_b64 = base64.b64encode(test_data).decode()
        
        self._storage.save_config(salt_b64, test_data_b64)
        self._is_unlocked = True
        self._entries = {}
    
    def unlock_vault(self, master_password: str) -> bool:
        """
        Unlock existing vault with master password.
        
        Args:
            master_password: Master password for the vault.
            
        Returns:
            True if unlock successful, False if password incorrect.
            
        Raises:
            FileNotFoundError: If vault doesn't exist.
        """
        if not self._storage.exists():
            raise FileNotFoundError("Vault does not exist")
        
        # Load vault config
        config = self._storage.load_config()
        
        # Restore salt and test data
        salt = base64.b64decode(config["salt"])
        test_data = base64.b64decode(config["test_data"])
        
        # Verify password
        self._encryption = EncryptionService(salt)
        if not self._encryption.verify_password(master_password, test_data):
            return False
        
        # Initialize encryption with verified password
        self._encryption.initialize_with_password(master_password)
        
        # Load and decrypt entries from database
        self._load_entries_from_db()
        
        self._is_unlocked = True
        return True
    
    def lock_vault(self) -> None:
        """Lock the vault and clear decrypted data from memory."""
        self._is_unlocked = False
        self._entries.clear()
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password.
        
        Args:
            old_password: Current master password.
            new_password: New master password.
            
        Returns:
            True if successful, False if old password incorrect.
        """
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked to change password")
        
        # Create new encryption service with new password
        new_encryption = EncryptionService()
        new_encryption.initialize_with_password(new_password)
        
        # Re-encrypt and save all entries
        for entry_id, entry in self._entries.items():
            encrypted_password = new_encryption.encrypt(entry.password)
            entry_data = entry.to_dict()
            entry_data["password"] = encrypted_password
            self._storage.save_entry(entry_data)
        
        # Create new test data and save config
        test_data = new_encryption.encrypt("vault_initialized")
        salt_b64 = base64.b64encode(new_encryption.salt).decode()
        test_data_b64 = base64.b64encode(test_data).decode()
        
        self._storage.save_config(salt_b64, test_data_b64)
        self._encryption = new_encryption
        
        return True
    
    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = ""
    ) -> PasswordEntry:
        """
        Add a new password entry.
        
        Args:
            title: Entry title/name.
            username: Username/email.
            password: Password (will be encrypted).
            url: Associated URL.
            notes: Additional notes.
            
        Returns:
            Created password entry.
            
        Raises:
            ValueError: If vault is locked.
        """
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked")
        
        # Generate unique ID
        entry_id = self._generate_id()
        
        # Create entry
        now = datetime.now().isoformat()
        entry = PasswordEntry(
            id=entry_id,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=now,
            modified_at=now
        )
        
        self._entries[entry_id] = entry
        self._save_entry_to_db(entry)
        
        return entry
    
    def update_entry(
        self,
        entry_id: str,
        title: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None
    ) -> PasswordEntry:
        """
        Update an existing password entry.
        
        Args:
            entry_id: ID of entry to update.
            title: New title (if provided).
            username: New username (if provided).
            password: New password (if provided).
            url: New URL (if provided).
            notes: New notes (if provided).
            
        Returns:
            Updated password entry.
            
        Raises:
            ValueError: If vault is locked or entry not found.
        """
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked")
        
        if entry_id not in self._entries:
            raise ValueError(f"Entry not found: {entry_id}")
        
        entry = self._entries[entry_id]
        
        # Update fields
        if title is not None:
            entry.title = title
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if url is not None:
            entry.url = url
        if notes is not None:
            entry.notes = notes
        
        entry.modified_at = datetime.now().isoformat()
        
        self._save_entry_to_db(entry)
        return entry
    
    def delete_entry(self, entry_id: str) -> None:
        """
        Delete a password entry.
        
        Args:
            entry_id: ID of entry to delete.
            
        Raises:
            ValueError: If vault is locked or entry not found.
        """
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked")
        
        if entry_id not in self._entries:
            raise ValueError(f"Entry not found: {entry_id}")
        
        del self._entries[entry_id]
        self._storage.delete_entry(entry_id)
    
    def get_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Get a specific password entry.
        
        Args:
            entry_id: ID of entry to retrieve.
            
        Returns:
            Password entry or None if not found.
        """
        return self._entries.get(entry_id)
    
    def get_all_entries(self) -> List[PasswordEntry]:
        """
        Get all password entries.
        
        Returns:
            List of all password entries.
            
        Raises:
            ValueError: If vault is locked.
        """
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked")
        
        return list(self._entries.values())
    
    def search_entries(self, query: str) -> List[PasswordEntry]:
        """
        Search entries by title, username, or URL.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching password entries.
        """
        if not self._is_unlocked:
            return []
        
        query_lower = query.lower()
        results = []
        
        for entry in self._entries.values():
            if (query_lower in entry.title.lower() or
                query_lower in entry.username.lower() or
                query_lower in entry.url.lower()):
                results.append(entry)
        
        return results
    
    def generate_password(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Password length.
            use_uppercase: Include uppercase letters.
            use_lowercase: Include lowercase letters.
            use_digits: Include digits.
            use_symbols: Include symbols.
            
        Returns:
            Generated password.
        """
        return PasswordGenerator.generate(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_symbols=use_symbols
        )
    
    def export_vault(self, export_path: str) -> None:
        """
        Export vault to a backup file.
        
        Args:
            export_path: Path where backup should be saved.
        """
        self._storage.backup(export_path)
    
    def _generate_id(self) -> str:
        """Generate a unique ID for an entry."""
        import uuid
        return str(uuid.uuid4())
    
    def _load_entries_from_db(self) -> None:
        """Load and decrypt entries from database."""
        self._entries.clear()
        
        entries_data = self._storage.load_all_entries()
        
        for entry_data in entries_data:
            # Decrypt password
            encrypted_password = entry_data["password"]
            decrypted_password = self._encryption.decrypt(encrypted_password)
            
            # Create entry
            entry_dict = {
                'id': entry_data['id'],
                'title': entry_data['title'],
                'username': entry_data['username'],
                'password': decrypted_password,
                'url': entry_data['url'] or '',
                'notes': entry_data['notes'] or '',
                'created_at': entry_data['created_at'],
                'modified_at': entry_data['modified_at']
            }
            
            self._entries[entry_data['id']] = PasswordEntry.from_dict(entry_dict)
    
    def _save_entry_to_db(self, entry: PasswordEntry) -> None:
        """Encrypt and save a single entry to database."""
        encrypted_password = self._encryption.encrypt(entry.password)
        
        entry_data = {
            'id': entry.id,
            'title': entry.title,
            'username': entry.username,
            'password': encrypted_password,  # Store as bytes
            'url': entry.url,
            'notes': entry.notes,
            'created_at': entry.created_at,
            'modified_at': entry.modified_at
        }
        
        self._storage.save_entry(entry_data)
