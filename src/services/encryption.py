"""
Encryption module for secure password storage.
Uses Fernet symmetric encryption from cryptography library.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Optional


class EncryptionService:
    """
    Handles encryption and decryption of password data using Fernet.
    Uses PBKDF2 for key derivation from master password.
    """
    
    def __init__(self, salt: Optional[bytes] = None):
        """
        Initialize the encryption service.
        
        Args:
            salt: Optional salt for key derivation. If None, generates new salt.
        """
        self._salt = salt if salt else os.urandom(16)
        self._fernet: Optional[Fernet] = None
    
    @property
    def salt(self) -> bytes:
        """Get the salt used for key derivation."""
        return self._salt
    
    def initialize_with_password(self, master_password: str) -> None:
        """
        Initialize encryption with master password.
        
        Args:
            master_password: The master password for encryption/decryption.
        """
        key = self._derive_key(master_password, self._salt)
        self._fernet = Fernet(key)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: The password to derive key from.
            salt: Salt for key derivation.
            
        Returns:
            Base64 encoded encryption key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt data using Fernet.
        
        Args:
            data: Plain text data to encrypt.
            
        Returns:
            Encrypted data as bytes.
            
        Raises:
            ValueError: If encryption service not initialized with password.
        """
        if not self._fernet:
            raise ValueError("Encryption service not initialized with password")
        
        return self._fernet.encrypt(data.encode())
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt data using Fernet.
        
        Args:
            encrypted_data: Encrypted data as bytes.
            
        Returns:
            Decrypted plain text data.
            
        Raises:
            ValueError: If encryption service not initialized with password.
        """
        if not self._fernet:
            raise ValueError("Encryption service not initialized with password")
        
        return self._fernet.decrypt(encrypted_data).decode()
    
    def verify_password(self, password: str, test_data: bytes) -> bool:
        """
        Verify if a password is correct by attempting decryption.
        
        Args:
            password: Password to verify.
            test_data: Encrypted test data.
            
        Returns:
            True if password is correct, False otherwise.
        """
        try:
            key = self._derive_key(password, self._salt)
            fernet = Fernet(key)
            fernet.decrypt(test_data)
            return True
        except Exception:
            return False
