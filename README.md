# PyPass

A secure, production-ready desktop password manager with SQLite3 storage, multi-page interface, and dark/light themes.

## Features

### SQLite3 Database Storage
- High-performance database backend
- Optimized queries with indexes
- Atomic transactions for data integrity
- Built-in statistics tracking

### Multi-Page Interface
- **Authentication Page**: Clean login/create vault interface
- **Passwords Page**: Full-featured password management with search
- **Settings Page**: Theme switching, vault management, security options
- Navigation sidebar for easy page switching

### Dark/Light Theme Support
- Toggle between dark and light themes
- Modern UI design with ttkbootstrap
- Smooth theme transitions

### Clean Architecture
```
PyPass/
├── main.py                          # Application entry point
├── services/                        # Business logic layer
│   ├── encryption.py               # Encryption service
│   ├── storage.py                  # SQLite3 storage
│   ├── password_generator.py       # Password generation
│   └── password_manager.py         # Core business logic
└── ui/                             # User interface layer
    ├── app.py                      # Main app controller
    ├── pages/                      # Page components
    │   ├── auth_page.py           # Authentication
    │   ├── main_page.py           # Password management
    │   └── settings_page.py       # Settings
    └── dialogs/                    # Dialog components
        ├── add_edit_dialog.py     # Add/Edit password
        └── generator_dialog.py    # Password generator
```

## Security

- **SQLite3 Encryption**: Encrypted storage in database
- **PBKDF2 + Fernet**: Military-grade AES-128 encryption
- **100,000 Iterations**: Brute-force resistant key derivation
- **Unique Salt**: Per-vault salt prevents rainbow attacks

## Usage

```bash
python main.py
```

### Navigation
- **Passwords**: Manage all your passwords
- **Settings**: Configure theme, import/export, change master password
- **Lock**: Secure your vault when away

### Importing Passwords
1. Go to Settings → Vault Management
2. Click "📥 Import"
3. Select an exported vault database file (.db)
4. Confirm the import
5. Passwords will be imported (duplicates automatically skipped)

**Note**: Import only accepts vault database files exported from PyPass. This ensures compatibility and maintains encryption integrity.

### Theme Switching
Go to Settings → Appearance → Choose Dark 🌙 or Light ☀️

## Database Schema

```sql
-- Configuration table
CREATE TABLE vault_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Passwords table
CREATE TABLE passwords (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password BLOB NOT NULL,    -- Encrypted
    url TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    modified_at TEXT NOT NULL
);
```

## Architecture Principles

- **Separation of Concerns**: Services ↔ UI completely decoupled
- **OOP Design**: Single responsibility, dependency injection
- **Scalability**: Modular page-based architecture
- **Maintainability**: Clear structure, type hints, docstrings
