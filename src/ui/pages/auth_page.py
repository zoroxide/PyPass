"""
Authentication page for vault login and creation.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from typing import Callable, Optional


class AuthPage(ttk.Frame):
    """Page for authenticating with master password."""
    
    def __init__(
        self,
        parent,
        on_auth_success: Callable,
        vault_exists: bool,
        **kwargs
    ):
        """
        Initialize auth page.
        
        Args:
            parent: Parent widget.
            on_auth_success: Callback when authentication succeeds.
            vault_exists: Whether vault already exists.
        """
        super().__init__(parent, **kwargs)
        self.on_auth_success = on_auth_success
        self.vault_exists = vault_exists
        
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create auth page widgets."""
        # Center frame
        center_frame = ttk.Frame(self)
        center_frame.place(relx=0.5, rely=0.5, anchor=CENTER)
        
        # Title
        ttk.Label(
            center_frame,
            text="🔐 PyPass",
            font=("Segoe UI", 32, "bold"),
            bootstyle=PRIMARY
        ).pack(pady=30)
        
        # Subtitle
        if self.vault_exists:
            subtitle = "Welcome Back!"
            instruction = "Enter your master password to unlock the vault"
        else:
            subtitle = "Get Started"
            instruction = "Create a master password to secure your vault"
        
        ttk.Label(
            center_frame,
            text=subtitle,
            font=("Segoe UI", 18),
            bootstyle=SECONDARY
        ).pack(pady=(0, 10))
        
        ttk.Label(
            center_frame,
            text=instruction,
            font=("Segoe UI", 10)
        ).pack(pady=(0, 20))
        
        # Form frame
        form_frame = ttk.Frame(center_frame)
        form_frame.pack(pady=10)
        
        # Password entry
        ttk.Label(
            form_frame,
            text="Master Password",
            font=("Segoe UI", 11, "bold")
        ).grid(row=0, column=0, sticky=W, pady=(0, 5))
        
        self.password_var = ttk.StringVar()
        password_entry = ttk.Entry(
            form_frame,
            textvariable=self.password_var,
            show="●",
            width=35,
            font=("Segoe UI", 12)
        )
        password_entry.grid(row=1, column=0, pady=(0, 15))
        password_entry.focus()
        
        # Confirm password (only for new vault)
        self.confirm_var = ttk.StringVar()
        self.confirm_entry = None
        
        if not self.vault_exists:
            ttk.Label(
                form_frame,
                text="Confirm Password",
                font=("Segoe UI", 11, "bold")
            ).grid(row=2, column=0, sticky=W, pady=(0, 5))
            
            self.confirm_entry = ttk.Entry(
                form_frame,
                textvariable=self.confirm_var,
                show="●",
                width=35,
                font=("Segoe UI", 12)
            )
            self.confirm_entry.grid(row=3, column=0, pady=(0, 15))
        
        # Submit button
        submit_btn = ttk.Button(
            form_frame,
            text="Unlock Vault" if self.vault_exists else "Create Vault",
            command=self._on_submit,
            bootstyle=SUCCESS,
            width=35
        )
        submit_btn.grid(row=4, column=0, pady=10)
        
        # Bind Enter key
        password_entry.bind("<Return>", lambda e: self._on_submit())
        if self.confirm_entry:
            self.confirm_entry.bind("<Return>", lambda e: self._on_submit())
        
        # Info label
        if not self.vault_exists:
            info_label = ttk.Label(
                form_frame,
                text="⚠️ Remember this password!\nIt cannot be recovered if forgotten.",
                font=("Segoe UI", 9),
                bootstyle=WARNING,
                justify=CENTER
            )
            info_label.grid(row=5, column=0, pady=15)
    
    def _on_submit(self) -> None:
        """Handle form submission."""
        password = self.password_var.get()
        
        if not password:
            Messagebox.show_error("Please enter a password", "Error")
            return
        
        if self.vault_exists:
            # Try to unlock
            self.on_auth_success(password)
        else:
            # Create new vault
            confirm = self.confirm_var.get()
            
            if password != confirm:
                Messagebox.show_error("Passwords do not match", "Error")
                return
            
            if len(password) < 8:
                Messagebox.show_error(
                    "Master password must be at least 8 characters",
                    "Error"
                )
                return
            
            self.on_auth_success(password)
