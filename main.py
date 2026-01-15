"""
PyPass - Secure desktop application for managing passwords.

A production-ready password manager with SQLite3 storage, encryption,
password generation, and a modern multi-page GUI with dark/light themes.

Features:
- SQLite3 database storage
- PBKDF2 + Fernet encryption
- Multi-page interface with navigation
- Dark/Light theme switcher
- Password generator with strength indicator
- Search functionality
- Export/backup capabilities

Author: Loay Mohamed
Date: 2026
"""

from src.services.encryption import EncryptionService
from src.services.storage import StorageService
from src.services.password_manager import PasswordManager

from src.ui.app import PasswordManagerApp


def main():
    """Main entry point for the PyPass application."""
    # Initialize services
    storage_service = StorageService()
    encryption_service = EncryptionService()
    
    # Initialize password manager with services
    password_manager = PasswordManager(storage_service, encryption_service)
    
    # Launch UI
    app = PasswordManagerApp(password_manager)
    app.run()


if __name__ == "__main__":
    main()
