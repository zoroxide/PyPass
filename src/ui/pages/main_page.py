"""
Main page for password management.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
import pyperclip
from typing import Callable, Optional
from datetime import datetime

from ...services import PasswordEntry


class MainPage(ttk.Frame):
    """Main password management interface."""
    
    def __init__(
        self,
        parent,
        password_manager,
        on_add: Callable,
        on_edit: Callable,
        on_generate: Callable,
        **kwargs
    ):
        """
        Initialize main page.
        
        Args:
            parent: Parent widget.
            password_manager: Password manager service instance.
            on_add: Callback for adding new entry.
            on_edit: Callback for editing entry.
            on_generate: Callback for password generator.
        """
        super().__init__(parent, **kwargs)
        self.pm = password_manager
        self.on_add = on_add
        self.on_edit = on_edit
        self.on_generate = on_generate
        
        self.current_entries = []
        self.selected_entry: Optional[PasswordEntry] = None
        self.password_hidden = True
        
        self._create_widgets()
        self.refresh_entry_list()
    
    def _create_widgets(self) -> None:
        """Create main page widgets."""
        # Toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=X, padx=10, pady=10)
        
        # Left side buttons
        left_frame = ttk.Frame(toolbar)
        left_frame.pack(side=LEFT)
        
        ttk.Button(
            left_frame,
            text="➕ Add Password",
            command=self.on_add,
            bootstyle=SUCCESS,
            width=15
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            left_frame,
            text="🎲 Generate",
            command=self.on_generate,
            bootstyle=INFO,
            width=15
        ).pack(side=LEFT, padx=5)
        
        # Search
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=LEFT, padx=30)
        
        ttk.Label(search_frame, text="🔍", font=("Segoe UI", 12)).pack(side=LEFT, padx=5)
        
        self.search_var = ttk.StringVar()
        self.search_var.trace("w", lambda *args: self._on_search())
        
        ttk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=35,
            font=("Segoe UI", 10)
        ).pack(side=LEFT)
        
        # Content area (split into list and details)
        content_paned = ttk.PanedWindow(self, orient=HORIZONTAL)
        content_paned.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))
        
        # Left panel - Entry list
        list_frame = self._create_entry_list()
        content_paned.add(list_frame, weight=2)
        
        # Right panel - Entry details
        details_frame = self._create_entry_details()
        content_paned.add(details_frame, weight=1)
    
    def _create_entry_list(self) -> ttk.Frame:
        """Create entry list panel."""
        list_frame = ttk.LabelFrame(self, text="  Passwords  ", padding=10)
        
        # Treeview for entries
        columns = ("title", "username", "url")
        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="tree headings",
            selectmode=BROWSE,
            bootstyle=INFO
        )
        
        # Configure columns
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=35, stretch=NO)
        self.tree.heading("title", text="Title", anchor=W)
        self.tree.column("title", width=250)
        self.tree.heading("username", text="Username", anchor=W)
        self.tree.column("username", width=220)
        self.tree.heading("url", text="URL", anchor=W)
        self.tree.column("url", width=250)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_entry_select)
        
        # Empty state label
        self.empty_label = ttk.Label(
            list_frame,
            text="No passwords yet.\nClick '➕ Add Password' to get started!",
            font=("Segoe UI", 11),
            bootstyle=SECONDARY,
            justify=CENTER
        )
        
        return list_frame
    
    def _create_entry_details(self) -> ttk.Frame:
        """Create entry details panel."""
        details_frame = ttk.LabelFrame(self, text="  Details  ", padding=15)
        
        # Create form
        form_frame = ttk.Frame(details_frame)
        form_frame.pack(fill=BOTH, expand=YES)
        
        row = 0
        
        # Title
        ttk.Label(
            form_frame,
            text="Title:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=row, column=0, sticky=W, pady=8)
        
        self.detail_title = ttk.Label(
            form_frame,
            text="",
            font=("Segoe UI", 10),
            wraplength=300
        )
        self.detail_title.grid(row=row, column=1, sticky=W, pady=8, padx=10)
        row += 1
        
        # Username
        ttk.Label(
            form_frame,
            text="Username:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=row, column=0, sticky=W, pady=8)
        
        username_frame = ttk.Frame(form_frame)
        username_frame.grid(row=row, column=1, sticky=W, pady=8, padx=10)
        
        self.detail_username = ttk.Label(
            username_frame,
            text="",
            font=("Segoe UI", 10)
        )
        self.detail_username.pack(side=LEFT)
        
        ttk.Button(
            username_frame,
            text="📋",
            command=lambda: self._copy_to_clipboard("username"),
            bootstyle=(SECONDARY, OUTLINE),
            width=4
        ).pack(side=LEFT, padx=5)
        row += 1
        
        # Password
        ttk.Label(
            form_frame,
            text="Password:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=row, column=0, sticky=W, pady=8)
        
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=row, column=1, sticky=W, pady=8, padx=10)
        
        self.detail_password = ttk.Label(
            password_frame,
            text="",
            font=("Segoe UI", 10)
        )
        self.detail_password.pack(side=LEFT)
        
        ttk.Button(
            password_frame,
            text="👁",
            command=self._toggle_password_visibility,
            bootstyle=(SECONDARY, OUTLINE),
            width=4
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            password_frame,
            text="📋",
            command=lambda: self._copy_to_clipboard("password"),
            bootstyle=(SECONDARY, OUTLINE),
            width=4
        ).pack(side=LEFT)
        row += 1
        
        # URL
        ttk.Label(
            form_frame,
            text="URL:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=row, column=0, sticky=W, pady=8)
        
        url_frame = ttk.Frame(form_frame)
        url_frame.grid(row=row, column=1, sticky=W, pady=8, padx=10)
        
        self.detail_url = ttk.Label(
            url_frame,
            text="",
            font=("Segoe UI", 10),
            wraplength=300
        )
        self.detail_url.pack(side=LEFT)
        
        ttk.Button(
            url_frame,
            text="📋",
            command=lambda: self._copy_to_clipboard("url"),
            bootstyle=(SECONDARY, OUTLINE),
            width=4
        ).pack(side=LEFT, padx=5)
        row += 1
        
        # Notes
        ttk.Label(
            form_frame,
            text="Notes:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=row, column=0, sticky=NW, pady=8)
        
        self.detail_notes = ttk.Text(
            form_frame,
            height=5,
            width=35,
            font=("Segoe UI", 9),
            state=DISABLED,
            wrap=WORD
        )
        self.detail_notes.grid(row=row, column=1, sticky=W, pady=8, padx=10)
        row += 1
        
        # Separator
        ttk.Separator(form_frame, orient=HORIZONTAL).grid(
            row=row, column=0, columnspan=2, sticky=EW, pady=15
        )
        row += 1
        
        # Timestamps
        ttk.Label(
            form_frame,
            text="Created:",
            font=("Segoe UI", 9)
        ).grid(row=row, column=0, sticky=W, pady=5)
        
        self.detail_created = ttk.Label(
            form_frame,
            text="",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        )
        self.detail_created.grid(row=row, column=1, sticky=W, pady=5, padx=10)
        row += 1
        
        ttk.Label(
            form_frame,
            text="Modified:",
            font=("Segoe UI", 9)
        ).grid(row=row, column=0, sticky=W, pady=5)
        
        self.detail_modified = ttk.Label(
            form_frame,
            text="",
            font=("Segoe UI", 9),
            bootstyle=SECONDARY
        )
        self.detail_modified.grid(row=row, column=1, sticky=W, pady=5, padx=10)
        row += 1
        
        # Action buttons
        button_frame = ttk.Frame(details_frame)
        button_frame.pack(fill=X, pady=15)
        
        ttk.Button(
            button_frame,
            text="✏️ Edit",
            command=self._edit_entry,
            bootstyle=PRIMARY,
            width=15
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="🗑️ Delete",
            command=self._delete_entry,
            bootstyle=DANGER,
            width=15
        ).pack(side=LEFT, padx=5)
        
        return details_frame
    
    def refresh_entry_list(self, entries=None) -> None:
        """Refresh the entry list display."""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get entries
        if entries is None:
            entries = self.pm.get_all_entries()
        
        self.current_entries = entries
        
        # Show/hide empty state
        if not entries:
            self.tree.pack_forget()
            self.empty_label.place(relx=0.5, rely=0.5, anchor=CENTER)
        else:
            self.empty_label.place_forget()
            self.tree.pack(side=LEFT, fill=BOTH, expand=YES)
        
        # Sort by title
        entries.sort(key=lambda e: e.title.lower())
        
        # Add to tree
        for entry in entries:
            self.tree.insert(
                "",
                END,
                iid=entry.id,
                text="🔑",
                values=(entry.title, entry.username, entry.url or "")
            )
    
    def _on_entry_select(self, event) -> None:
        """Handle entry selection."""
        selection = self.tree.selection()
        if not selection:
            return
        
        entry_id = selection[0]
        self.selected_entry = self.pm.get_entry(entry_id)
        
        if self.selected_entry:
            self._display_entry_details(self.selected_entry)
    
    def _display_entry_details(self, entry: PasswordEntry) -> None:
        """Display entry details in the details panel."""
        self.detail_title.config(text=entry.title)
        self.detail_username.config(text=entry.username)
        
        # Hide password by default
        self.password_hidden = True
        self.detail_password.config(text="●●●●●●●●●●")
        
        self.detail_url.config(text=entry.url or "N/A")
        
        # Notes
        self.detail_notes.config(state=NORMAL)
        self.detail_notes.delete("1.0", END)
        self.detail_notes.insert("1.0", entry.notes or "No notes")
        self.detail_notes.config(state=DISABLED)
        
        # Timestamps
        try:
            created = datetime.fromisoformat(entry.created_at)
            self.detail_created.config(text=created.strftime("%b %d, %Y %I:%M %p"))
        except:
            self.detail_created.config(text=entry.created_at)
        
        try:
            modified = datetime.fromisoformat(entry.modified_at)
            self.detail_modified.config(text=modified.strftime("%b %d, %Y %I:%M %p"))
        except:
            self.detail_modified.config(text=entry.modified_at)
    
    def _toggle_password_visibility(self) -> None:
        """Toggle password visibility."""
        if not self.selected_entry:
            return
        
        if self.password_hidden:
            self.detail_password.config(text=self.selected_entry.password)
            self.password_hidden = False
        else:
            self.detail_password.config(text="●●●●●●●●●●")
            self.password_hidden = True
    
    def _copy_to_clipboard(self, field: str) -> None:
        """Copy field value to clipboard."""
        if not self.selected_entry:
            return
        
        value = ""
        if field == "username":
            value = self.selected_entry.username
        elif field == "password":
            value = self.selected_entry.password
        elif field == "url":
            value = self.selected_entry.url
        
        if value:
            pyperclip.copy(value)
            Messagebox.show_info(
                f"{field.capitalize()} copied to clipboard!",
                "Copied",
                alert=True
            )
    
    def _on_search(self) -> None:
        """Handle search input."""
        query = self.search_var.get()
        
        if not query:
            self.refresh_entry_list()
        else:
            results = self.pm.search_entries(query)
            self.refresh_entry_list(results)
    
    def _edit_entry(self) -> None:
        """Edit selected entry."""
        if not self.selected_entry:
            Messagebox.show_warning("Please select an entry to edit", "No Selection")
            return
        
        self.on_edit(self.selected_entry)
    
    def _delete_entry(self) -> None:
        """Delete selected entry."""
        if not self.selected_entry:
            Messagebox.show_warning("Please select an entry to delete", "No Selection")
            return
        
        result = Messagebox.show_question(
            f"Are you sure you want to delete '{self.selected_entry.title}'?\nThis action cannot be undone.",
            "Confirm Delete",
            buttons=["Yes:danger", "No:secondary"]
        )
        
        if result == "Yes":
            self.pm.delete_entry(self.selected_entry.id)
            self.selected_entry = None
            self.refresh_entry_list()
            
            # Clear details
            self._clear_details()
            
            Messagebox.show_info("Password deleted successfully!", "Success", alert=True)
    
    def _clear_details(self) -> None:
        """Clear the details panel."""
        self.detail_title.config(text="")
        self.detail_username.config(text="")
        self.detail_password.config(text="")
        self.detail_url.config(text="")
        self.detail_notes.config(state=NORMAL)
        self.detail_notes.delete("1.0", END)
        self.detail_notes.config(state=DISABLED)
        self.detail_created.config(text="")
        self.detail_modified.config(text="")
