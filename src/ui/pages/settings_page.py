"""
Settings page for application configuration.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import filedialog
from typing import Callable


class SettingsPage(ttk.Frame):
    """Settings and configuration page."""
    
    def __init__(
        self,
        parent,
        password_manager,
        on_theme_change: Callable,
        current_theme: str,
        on_lock: Callable,
        **kwargs
    ):
        """
        Initialize settings page.
        
        Args:
            parent: Parent widget.
            password_manager: Password manager service instance.
            on_theme_change: Callback for theme changes.
            current_theme: Current theme name.
            on_lock: Callback for locking vault.
        """
        super().__init__(parent, **kwargs)
        self.pm = password_manager
        self.on_theme_change = on_theme_change
        self.current_theme = current_theme
        self.on_lock = on_lock
        
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create settings page widgets."""
        # Main container with padding
        container = ttk.Frame(self)
        container.pack(fill=BOTH, expand=YES, padx=30, pady=20)
        
        # Page title
        ttk.Label(
            container,
            text="⚙️ Settings",
            font=("Segoe UI", 24, "bold"),
            bootstyle=PRIMARY
        ).pack(anchor=W, pady=(0, 20))
        
        # Appearance section
        self._create_appearance_section(container)
        
        # Vault section
        self._create_vault_section(container)
        
        # Security section
        self._create_security_section(container)
        
        # About section
        self._create_about_section(container)
    
    def _create_appearance_section(self, parent: ttk.Frame) -> None:
        """Create appearance settings section."""
        section = ttk.LabelFrame(
            parent,
            text="  Appearance  ",
            padding=20
        )
        section.pack(fill=X, pady=(0, 15))
        
        # Theme selection
        theme_frame = ttk.Frame(section)
        theme_frame.pack(fill=X, pady=10)
        
        ttk.Label(
            theme_frame,
            text="Theme:",
            font=("Segoe UI", 11, "bold")
        ).pack(side=LEFT, padx=(0, 20))
        
        # Dark/Light toggle
        theme_btn_frame = ttk.Frame(theme_frame)
        theme_btn_frame.pack(side=LEFT)
        
        self.dark_btn = ttk.Button(
            theme_btn_frame,
            text="🌙 Dark",
            command=lambda: self._change_theme("darkly"),
            bootstyle=DARK if self.current_theme == "darkly" else (SECONDARY, OUTLINE),
            width=12
        )
        self.dark_btn.pack(side=LEFT, padx=5)
        
        self.light_btn = ttk.Button(
            theme_btn_frame,
            text="☀️ Light",
            command=lambda: self._change_theme("flatly"),
            bootstyle=LIGHT if self.current_theme == "flatly" else (SECONDARY, OUTLINE),
            width=12
        )
        self.light_btn.pack(side=LEFT, padx=5)
    
    def _create_vault_section(self, parent: ttk.Frame) -> None:
        """Create vault management section."""
        section = ttk.LabelFrame(
            parent,
            text="  Vault Management  ",
            padding=20
        )
        section.pack(fill=X, pady=(0, 15))
        
        # Import passwords
        import_frame = ttk.Frame(section)
        import_frame.pack(fill=X, pady=10)
        
        import_info = ttk.Frame(import_frame)
        import_info.pack(side=LEFT, fill=X, expand=YES)
        
        ttk.Label(
            import_info,
            text="Import Passwords",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor=W)
        
        ttk.Label(
            import_info,
            text="Import passwords from exported vault database (.db file)",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W)
        
        ttk.Button(
            import_frame,
            text="📥 Import",
            command=self._import_passwords,
            bootstyle=SUCCESS,
            width=15
        ).pack(side=RIGHT, padx=10)
        
        ttk.Separator(section, orient=HORIZONTAL).pack(fill=X, pady=15)
        
        # Export backup
        export_frame = ttk.Frame(section)
        export_frame.pack(fill=X, pady=10)
        
        export_info = ttk.Frame(export_frame)
        export_info.pack(side=LEFT, fill=X, expand=YES)
        
        ttk.Label(
            export_info,
            text="Export Vault",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor=W)
        
        ttk.Label(
            export_info,
            text="Create an encrypted backup of your vault",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W)
        
        ttk.Button(
            export_frame,
            text="💾 Export",
            command=self._export_vault,
            bootstyle=INFO,
            width=15
        ).pack(side=RIGHT, padx=10)
        
        ttk.Separator(section, orient=HORIZONTAL).pack(fill=X, pady=15)
        
        # Vault statistics
        stats_frame = ttk.Frame(section)
        stats_frame.pack(fill=X, pady=10)
        
        ttk.Label(
            stats_frame,
            text="Vault Statistics",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor=W, pady=(0, 10))
        
        # Get stats
        try:
            stats = self.pm._storage.get_stats()
            
            stats_grid = ttk.Frame(stats_frame)
            stats_grid.pack(fill=X)
            
            ttk.Label(
                stats_grid,
                text=f"📊 Total Passwords:",
                font=("Segoe UI", 10)
            ).grid(row=0, column=0, sticky=W, pady=5)
            
            ttk.Label(
                stats_grid,
                text=str(stats.get('entry_count', 0)),
                font=("Segoe UI", 10, "bold"),
                bootstyle=PRIMARY
            ).grid(row=0, column=1, sticky=W, padx=20, pady=5)
            
            ttk.Label(
                stats_grid,
                text=f"📅 Last Modified:",
                font=("Segoe UI", 10)
            ).grid(row=1, column=0, sticky=W, pady=5)
            
            last_mod = stats.get('last_modified', 'Unknown')
            if last_mod != 'Unknown':
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_mod)
                    last_mod = dt.strftime("%b %d, %Y %I:%M %p")
                except:
                    pass
            
            ttk.Label(
                stats_grid,
                text=last_mod,
                font=("Segoe UI", 10),
                bootstyle=SECONDARY
            ).grid(row=1, column=1, sticky=W, padx=20, pady=5)
        except Exception as e:
            ttk.Label(
                stats_frame,
                text="Unable to load statistics",
                font=("Segoe UI", 9),
                bootstyle=DANGER
            ).pack(anchor=W)
    
    def _create_security_section(self, parent: ttk.Frame) -> None:
        """Create security settings section."""
        section = ttk.LabelFrame(
            parent,
            text="  Security  ",
            padding=20
        )
        section.pack(fill=X, pady=(0, 15))
        
        # Change master password
        change_pw_frame = ttk.Frame(section)
        change_pw_frame.pack(fill=X, pady=10)
        
        change_info = ttk.Frame(change_pw_frame)
        change_info.pack(side=LEFT, fill=X, expand=YES)
        
        ttk.Label(
            change_info,
            text="Change Master Password",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor=W)
        
        ttk.Label(
            change_info,
            text="Update your master password",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W)
        
        ttk.Button(
            change_pw_frame,
            text="🔑 Change",
            command=self._change_master_password,
            bootstyle=WARNING,
            width=15
        ).pack(side=RIGHT, padx=10)
        
        ttk.Separator(section, orient=HORIZONTAL).pack(fill=X, pady=15)
        
        # Lock vault
        lock_frame = ttk.Frame(section)
        lock_frame.pack(fill=X, pady=10)
        
        lock_info = ttk.Frame(lock_frame)
        lock_info.pack(side=LEFT, fill=X, expand=YES)
        
        ttk.Label(
            lock_info,
            text="Lock Vault",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor=W)
        
        ttk.Label(
            lock_info,
            text="Lock the vault and require password to unlock",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W)
        
        ttk.Button(
            lock_frame,
            text="🔒 Lock Now",
            command=self.on_lock,
            bootstyle=DANGER,
            width=15
        ).pack(side=RIGHT, padx=10)
    
    def _create_about_section(self, parent: ttk.Frame) -> None:
        """Create about section."""
        section = ttk.LabelFrame(
            parent,
            text="  About  ",
            padding=20
        )
        section.pack(fill=X, pady=(0, 15))
        
        about_info = ttk.Frame(section)
        about_info.pack(fill=X)
        
        ttk.Label(
            about_info,
            text="PyPass",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor=W, pady=(0, 5))
        
        ttk.Label(
            about_info,
            text="Version 1.0.0",
            font=("Segoe UI", 10),
            bootstyle=SECONDARY
        ).pack(anchor=W, pady=2)
        
        ttk.Label(
            about_info,
            text="Secure password management with encryption",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W, pady=2)
        
        ttk.Label(
            about_info,
            text="Built with Python, SQLite3, and ttkbootstrap",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).pack(anchor=W, pady=2)
    
    def _change_theme(self, theme_name: str) -> None:
        """Change application theme."""
        self.current_theme = theme_name
        self.on_theme_change(theme_name)
        
        # Update button styles to reflect current theme
        if theme_name == "darkly":
            self.dark_btn.config(bootstyle=DARK)
            self.light_btn.config(bootstyle=(SECONDARY, OUTLINE))
        else:
            self.dark_btn.config(bootstyle=(SECONDARY, OUTLINE))
            self.light_btn.config(bootstyle=LIGHT)
    
    def _import_passwords(self) -> None:
        """Import passwords from exported vault database."""
        file_path = filedialog.askopenfilename(
            title="Import Vault",
            filetypes=[
                ("Database files", "*.db"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            # Confirm import
            result = Messagebox.show_question(
                "Import passwords from the selected vault?\n\n"
                "⚠️ Note: Duplicate entries will be skipped.\n"
                "Existing passwords will not be overwritten.",
                "Confirm Import",
                buttons=["Import:success", "Cancel:secondary"],
                parent=self
            )
            
            if result != "Import":
                return
            
            try:
                import sqlite3
                import uuid
                
                imported_count = 0
                skipped_count = 0
                
                # Connect to import database
                import_conn = sqlite3.connect(file_path)
                import_conn.row_factory = sqlite3.Row
                import_cursor = import_conn.cursor()
                
                # Check if it's a valid vault database
                import_cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'"
                )
                if not import_cursor.fetchone():
                    raise ValueError("Invalid vault database file")
                
                # Get all passwords from import database
                import_cursor.execute("SELECT * FROM passwords")
                entries = import_cursor.fetchall()
                
                if not entries:
                    Messagebox.show_warning(
                        "The selected vault contains no passwords.",
                        "No Data",
                        parent=self
                    )
                    import_conn.close()
                    return
                
                # Get existing entry IDs to avoid duplicates
                existing_ids = {entry.id for entry in self.pm.get_all_entries()}
                
                # Import each entry
                for entry in entries:
                    entry_id = entry['id']
                    
                    # Skip if entry already exists
                    if entry_id in existing_ids:
                        skipped_count += 1
                        continue
                    
                    # Save directly to storage (already encrypted)
                    entry_data = {
                        'id': entry_id,
                        'title': entry['title'],
                        'username': entry['username'],
                        'password': entry['password'],  # Already encrypted
                        'url': entry['url'] or '',
                        'notes': entry['notes'] or '',
                        'created_at': entry['created_at'],
                        'modified_at': entry['modified_at']
                    }
                    
                    self.pm._storage.save_entry(entry_data)
                    imported_count += 1
                
                import_conn.close()
                
                # Reload entries in memory
                self.pm._load_entries_from_db()
                
                # Show results
                message = f"✅ Successfully imported {imported_count} password(s)!"
                if skipped_count > 0:
                    message += f"\n⏭️ Skipped {skipped_count} duplicate(s)."
                
                Messagebox.show_info(message, "Import Complete", parent=self)
                
            except Exception as e:
                Messagebox.show_error(
                    f"Failed to import passwords:\n{str(e)}",
                    "Import Error",
                    parent=self
                )
    
    def _export_vault(self) -> None:
        """Export vault to backup file."""
        file_path = filedialog.asksaveasfilename(
            title="Export Vault",
            defaultextension=".db",
            filetypes=[
                ("Database files", "*.db"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                self.pm.export_vault(file_path)
                Messagebox.show_info(
                    f"Vault successfully exported to:\n{file_path}",
                    "Export Complete",
                    parent=self
                )
            except Exception as e:
                Messagebox.show_error(
                    f"Failed to export vault:\n{str(e)}",
                    "Export Error",
                    parent=self
                )
    
    def _change_master_password(self) -> None:
        """Change master password."""
        # Create dialog
        dialog = ttk.Toplevel(self)
        dialog.title("Change Master Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Form
        form = ttk.Frame(dialog, padding=20)
        form.pack(fill=BOTH, expand=YES)
        
        ttk.Label(
            form,
            text="Change Master Password",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 20))
        
        # Current password
        ttk.Label(form, text="Current Password:", font=("Segoe UI", 10)).pack(anchor=W, pady=(10, 5))
        current_var = ttk.StringVar()
        ttk.Entry(form, textvariable=current_var, show="●", width=40).pack(pady=(0, 10))
        
        # New password
        ttk.Label(form, text="New Password:", font=("Segoe UI", 10)).pack(anchor=W, pady=(10, 5))
        new_var = ttk.StringVar()
        ttk.Entry(form, textvariable=new_var, show="●", width=40).pack(pady=(0, 10))
        
        # Confirm new password
        ttk.Label(form, text="Confirm New Password:", font=("Segoe UI", 10)).pack(anchor=W, pady=(10, 5))
        confirm_var = ttk.StringVar()
        ttk.Entry(form, textvariable=confirm_var, show="●", width=40).pack(pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(form)
        btn_frame.pack(pady=10)
        
        def on_submit():
            current = current_var.get()
            new = new_var.get()
            confirm = confirm_var.get()
            
            if not current or not new or not confirm:
                Messagebox.show_error("All fields are required", "Error", parent=dialog)
                return
            
            if new != confirm:
                Messagebox.show_error("New passwords do not match", "Error", parent=dialog)
                return
            
            if len(new) < 8:
                Messagebox.show_error("New password must be at least 8 characters", "Error", parent=dialog)
                return
            
            try:
                success = self.pm.change_master_password(current, new)
                if success:
                    Messagebox.show_info("Master password changed successfully!", "Success", parent=dialog)
                    dialog.destroy()
                else:
                    Messagebox.show_error("Current password is incorrect", "Error", parent=dialog)
            except Exception as e:
                Messagebox.show_error(f"Failed to change password:\n{str(e)}", "Error", parent=dialog)
        
        ttk.Button(
            btn_frame,
            text="Change Password",
            command=on_submit,
            bootstyle=SUCCESS,
            width=20
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            bootstyle=SECONDARY,
            width=20
        ).pack(side=LEFT, padx=5)
