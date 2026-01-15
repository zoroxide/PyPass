"""
Dialog for adding and editing password entries.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from typing import Optional, Callable

from ...services import PasswordEntry


class AddEditDialog(ttk.Toplevel):
    """Dialog for adding or editing a password entry."""
    
    def __init__(
        self,
        parent,
        password_manager,
        on_success: Callable,
        entry: Optional[PasswordEntry] = None,
        **kwargs
    ):
        """
        Initialize add/edit dialog.
        
        Args:
            parent: Parent widget.
            password_manager: Password manager service instance.
            on_success: Callback when entry is saved successfully.
            entry: Entry to edit (None for new entry).
        """
        super().__init__(parent, **kwargs)
        
        self.pm = password_manager
        self.on_success = on_success
        self.entry = entry
        self.is_edit_mode = entry is not None
        
        self.title("Edit Password" if self.is_edit_mode else "Add Password")
        self.geometry("550x600")
        self.resizable(False, False)
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        # Center dialog
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")
        
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create dialog widgets."""
        # Main container
        container = ttk.Frame(self, padding=20)
        container.pack(fill=BOTH, expand=YES)
        
        # Title
        ttk.Label(
            container,
            text="✏️ Edit Password" if self.is_edit_mode else "➕ Add New Password",
            font=("Segoe UI", 16, "bold"),
            bootstyle=PRIMARY
        ).pack(pady=(0, 20))
        
        # Form frame
        form = ttk.Frame(container)
        form.pack(fill=BOTH, expand=YES)
        
        # Title field
        ttk.Label(
            form,
            text="Title *",
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky=W, pady=(0, 5))
        
        self.title_var = ttk.StringVar(
            value=self.entry.title if self.entry else ""
        )
        ttk.Entry(
            form,
            textvariable=self.title_var,
            width=50,
            font=("Segoe UI", 10)
        ).grid(row=1, column=0, pady=(0, 15), sticky=W)
        
        # Username field
        ttk.Label(
            form,
            text="Username / Email *",
            font=("Segoe UI", 10, "bold")
        ).grid(row=2, column=0, sticky=W, pady=(0, 5))
        
        self.username_var = ttk.StringVar(
            value=self.entry.username if self.entry else ""
        )
        ttk.Entry(
            form,
            textvariable=self.username_var,
            width=50,
            font=("Segoe UI", 10)
        ).grid(row=3, column=0, pady=(0, 15), sticky=W)
        
        # Password field
        ttk.Label(
            form,
            text="Password *",
            font=("Segoe UI", 10, "bold")
        ).grid(row=4, column=0, sticky=W, pady=(0, 5))
        
        password_frame = ttk.Frame(form)
        password_frame.grid(row=5, column=0, pady=(0, 15), sticky=W)
        
        self.password_var = ttk.StringVar(
            value=self.entry.password if self.entry else ""
        )
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            width=40,
            font=("Segoe UI", 10),
            show="●"
        )
        self.password_entry.pack(side=LEFT)
        
        # Show/hide button
        self.password_visible = False
        self.toggle_btn = ttk.Button(
            password_frame,
            text="👁",
            command=self._toggle_password,
            bootstyle=(SECONDARY, OUTLINE),
            width=4
        )
        self.toggle_btn.pack(side=LEFT, padx=5)
        
        # Generate button
        ttk.Button(
            password_frame,
            text="🎲",
            command=self._generate_password,
            bootstyle=(INFO, OUTLINE),
            width=4
        ).pack(side=LEFT)
        
        # URL field
        ttk.Label(
            form,
            text="URL",
            font=("Segoe UI", 10, "bold")
        ).grid(row=6, column=0, sticky=W, pady=(0, 5))
        
        self.url_var = ttk.StringVar(
            value=self.entry.url if self.entry else ""
        )
        ttk.Entry(
            form,
            textvariable=self.url_var,
            width=50,
            font=("Segoe UI", 10)
        ).grid(row=7, column=0, pady=(0, 15), sticky=W)
        
        # Notes field
        ttk.Label(
            form,
            text="Notes",
            font=("Segoe UI", 10, "bold")
        ).grid(row=8, column=0, sticky=W, pady=(0, 5))
        
        self.notes_text = ttk.Text(
            form,
            height=6,
            width=50,
            font=("Segoe UI", 9),
            wrap=WORD
        )
        self.notes_text.grid(row=9, column=0, pady=(0, 20), sticky=W)
        
        if self.entry and self.entry.notes:
            self.notes_text.insert("1.0", self.entry.notes)
        
        # Required field note
        ttk.Label(
            form,
            text="* Required fields",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        ).grid(row=10, column=0, sticky=W, pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(container)
        button_frame.pack(fill=X, pady=10)
        
        ttk.Button(
            button_frame,
            text="💾 Save",
            command=self._on_save,
            bootstyle=SUCCESS,
            width=20
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.destroy,
            bootstyle=SECONDARY,
            width=20
        ).pack(side=LEFT, padx=5)
    
    def _toggle_password(self) -> None:
        """Toggle password visibility."""
        if self.password_visible:
            self.password_entry.config(show="●")
            self.password_visible = False
        else:
            self.password_entry.config(show="")
            self.password_visible = True
    
    def _generate_password(self) -> None:
        """Generate a random password."""
        password = self.pm.generate_password(length=16)
        self.password_var.set(password)
        Messagebox.show_info(
            "Password generated!\nClick 👁 to view it.",
            "Generated",
            parent=self,
            alert=True
        )
    
    def _on_save(self) -> None:
        """Handle save button click."""
        # Get values
        title = self.title_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        url = self.url_var.get().strip()
        notes = self.notes_text.get("1.0", END).strip()
        
        # Validate
        if not title or not username or not password:
            Messagebox.show_error(
                "Please fill in all required fields",
                "Validation Error",
                parent=self
            )
            return
        
        try:
            if self.is_edit_mode:
                # Update existing entry
                self.pm.update_entry(
                    self.entry.id,
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes
                )
                message = "Password updated successfully!"
            else:
                # Add new entry
                self.pm.add_entry(
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes
                )
                message = "Password added successfully!"
            
            Messagebox.show_info(message, "Success", parent=self.master, alert=True)
            self.on_success()
            self.destroy()
            
        except Exception as e:
            Messagebox.show_error(
                f"Failed to save password:\n{str(e)}",
                "Error",
                parent=self
            )
