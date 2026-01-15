"""
Main application controller with multi-page navigation and theme switching.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import PhotoImage
import os

from ..services import PasswordManager
from .pages.auth_page import AuthPage
from .pages.main_page import MainPage
from .pages.settings_page import SettingsPage
from .dialogs.add_edit_dialog import AddEditDialog
from .dialogs.generator_dialog import GeneratorDialog


class PasswordManagerApp:
    """Main application controller."""
    
    def __init__(self, password_manager: PasswordManager):
        """
        Initialize the application.
        
        Args:
            password_manager: Password manager service instance.
        """
        self.pm = password_manager
        self.current_theme = "darkly"  # Default theme
        
        # Create main window
        self.root = ttk.Window(themename=self.current_theme)
        self.root.title("PyPass")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        
        # Set window icon for title bar and taskbar
        try:
            import sys
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                base_path = sys._MEIPASS
            else:
                # Running as script
                base_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            # Try .ico first (best for Windows title bar and taskbar)
            ico_path = os.path.join(base_path, "assets", "icon.ico")
            if os.path.exists(ico_path):
                self.root.iconbitmap(ico_path)
            else:
                # Fallback to .png
                png_path = os.path.join(base_path, "assets", "icon.png")
                if os.path.exists(png_path):
                    icon = PhotoImage(file=png_path)
                    self.root.iconphoto(True, icon)
        except Exception:
            pass  # Silently fail if icon cannot be loaded
        
        # Current page reference
        self.current_page = None
        self.main_page = None
        
        # Show initial screen
        if self.pm._storage.exists():
            self._show_auth_page()
        else:
            self._show_auth_page()
    
    def run(self) -> None:
        """Start the application event loop."""
        self.root.mainloop()
    
    def _show_auth_page(self) -> None:
        """Show authentication page."""
        # Clear window
        self._clear_window()
        
        # Create auth page
        vault_exists = self.pm._storage.exists()
        auth_page = AuthPage(
            self.root,
            on_auth_success=self._on_auth_success,
            vault_exists=vault_exists
        )
        auth_page.pack(fill=BOTH, expand=YES)
        self.current_page = auth_page
    
    def _on_auth_success(self, password: str) -> None:
        """Handle successful authentication."""
        vault_exists = self.pm._storage.exists()
        
        if vault_exists:
            # Try to unlock
            if self.pm.unlock_vault(password):
                self._show_main_screen()
            else:
                Messagebox.show_error("Incorrect password", "Authentication Failed")
        else:
            # Create new vault
            try:
                self.pm.create_vault(password)
                Messagebox.show_info(
                    "Vault created successfully!\nYour passwords are now secure.",
                    "Success"
                )
                self._show_main_screen()
            except Exception as e:
                Messagebox.show_error(f"Failed to create vault:\n{str(e)}", "Error")
    
    def _show_main_screen(self) -> None:
        """Show main screen with navigation."""
        # Clear window
        self._clear_window()
        
        # Create container
        container = ttk.Frame(self.root)
        container.pack(fill=BOTH, expand=YES)
        
        # Create navigation sidebar
        self._create_navigation(container)
        
        # Create content area
        self.content_frame = ttk.Frame(container)
        self.content_frame.pack(side=RIGHT, fill=BOTH, expand=YES)
        
        # Show passwords page by default
        self._show_passwords_page()
    
    def _create_navigation(self, parent: ttk.Frame) -> None:
        """Create navigation sidebar."""
        nav_frame = ttk.Frame(parent, bootstyle=DARK)
        nav_frame.pack(side=LEFT, fill=Y)
        
        # App title
        title_frame = ttk.Frame(nav_frame, bootstyle=DARK)
        title_frame.pack(fill=X, pady=20, padx=15)
        
        ttk.Label(
            title_frame,
            text="🔐",
            font=("Segoe UI", 24),
            bootstyle=(INVERSE, DARK)
        ).pack()
        
        ttk.Label(
            title_frame,
            text="PyPass",
            font=("Segoe UI", 14, "bold"),
            bootstyle=(INVERSE, DARK),
            justify=CENTER
        ).pack()
        
        ttk.Separator(nav_frame, orient=HORIZONTAL).pack(fill=X, pady=15)
        
        # Navigation buttons
        nav_buttons = ttk.Frame(nav_frame, bootstyle=DARK)
        nav_buttons.pack(fill=BOTH, expand=YES, padx=10)
        
        self.nav_btn_passwords = ttk.Button(
            nav_buttons,
            text="🔑 Passwords",
            command=self._show_passwords_page,
            bootstyle=PRIMARY,
            width=18
        )
        self.nav_btn_passwords.pack(pady=5, fill=X)
        
        self.nav_btn_settings = ttk.Button(
            nav_buttons,
            text="⚙️ Settings",
            command=self._show_settings_page,
            bootstyle=(SECONDARY, OUTLINE),
            width=18
        )
        self.nav_btn_settings.pack(pady=5, fill=X)
        
        # Spacer
        ttk.Frame(nav_frame, bootstyle=DARK).pack(fill=BOTH, expand=YES)
        
        # Lock button at bottom
        ttk.Button(
            nav_frame,
            text="🔒 Lock Vault",
            command=self._lock_vault,
            bootstyle=DANGER,
            width=18
        ).pack(pady=15, padx=10)
    
    def _show_passwords_page(self) -> None:
        """Show passwords page."""
        self._clear_content()
        
        # Update navigation button styles
        self.nav_btn_passwords.config(bootstyle=PRIMARY)
        self.nav_btn_settings.config(bootstyle=(SECONDARY, OUTLINE))
        
        # Create main page
        self.main_page = MainPage(
            self.content_frame,
            self.pm,
            on_add=self._show_add_dialog,
            on_edit=self._show_edit_dialog,
            on_generate=self._show_generator_dialog
        )
        self.main_page.pack(fill=BOTH, expand=YES)
        self.current_page = self.main_page
    
    def _show_settings_page(self) -> None:
        """Show settings page."""
        self._clear_content()
        
        # Update navigation button styles
        self.nav_btn_passwords.config(bootstyle=(SECONDARY, OUTLINE))
        self.nav_btn_settings.config(bootstyle=PRIMARY)
        
        # Create settings page
        settings_page = SettingsPage(
            self.content_frame,
            self.pm,
            on_theme_change=self._change_theme,
            current_theme=self.current_theme,
            on_lock=self._lock_vault
        )
        settings_page.pack(fill=BOTH, expand=YES)
        self.current_page = settings_page
    
    def _show_add_dialog(self) -> None:
        """Show add password dialog."""
        AddEditDialog(
            self.root,
            self.pm,
            on_success=self._refresh_main_page
        )
    
    def _show_edit_dialog(self, entry) -> None:
        """Show edit password dialog."""
        AddEditDialog(
            self.root,
            self.pm,
            on_success=self._refresh_main_page,
            entry=entry
        )
    
    def _show_generator_dialog(self) -> None:
        """Show password generator dialog."""
        GeneratorDialog(self.root, self.pm)
    
    def _refresh_main_page(self) -> None:
        """Refresh the main page after changes."""
        if self.main_page:
            self.main_page.refresh_entry_list()
    
    def _change_theme(self, theme_name: str) -> None:
        """Change application theme."""
        self.current_theme = theme_name
        
        # Use ttkbootstrap's built-in theme switching
        style = ttk.Style.get_instance()
        style.theme_use(theme_name)
        
        # Update settings page if it's the current page
        if isinstance(self.current_page, SettingsPage):
            # Refresh settings page to update button styles
            self._show_settings_page()
    
    def _lock_vault(self) -> None:
        """Lock the vault."""
        result = Messagebox.show_question(
            "Lock the vault? You'll need to enter your master password again.",
            "Confirm Lock",
            buttons=["Yes:primary", "No:secondary"]
        )
        
        if result == "Yes":
            self.pm.lock_vault()
            self._show_auth_page()
    
    def _clear_window(self) -> None:
        """Clear all widgets from window."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def _clear_content(self) -> None:
        """Clear content frame."""
        if self.content_frame:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
