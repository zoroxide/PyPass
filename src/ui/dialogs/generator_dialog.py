"""
Dialog for generating secure passwords.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
import pyperclip
from typing import Callable

from ...services import PasswordGenerator


class GeneratorDialog(ttk.Toplevel):
    """Dialog for password generation."""
    
    def __init__(self, parent, password_manager, **kwargs):
        """
        Initialize generator dialog.
        
        Args:
            parent: Parent widget.
            password_manager: Password manager service instance.
        """
        super().__init__(parent, **kwargs)
        
        self.pm = password_manager
        
        self.title("Password Generator")
        self.geometry("500x550")
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
        self._generate()  # Generate initial password
    
    def _create_widgets(self) -> None:
        """Create dialog widgets."""
        # Main container
        container = ttk.Frame(self, padding=20)
        container.pack(fill=BOTH, expand=YES)
        
        # Title
        ttk.Label(
            container,
            text="🎲 Password Generator",
            font=("Segoe UI", 16, "bold"),
            bootstyle=PRIMARY
        ).pack(pady=(0, 20))
        
        # Generated password display
        ttk.Label(
            container,
            text="Generated Password:",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor=W, pady=(0, 5))
        
        self.password_display = ttk.Entry(
            container,
            font=("Courier New", 14, "bold"),
            width=40,
            state=READONLY,
            bootstyle=SUCCESS
        )
        self.password_display.pack(pady=(0, 10))
        
        # Copy button
        ttk.Button(
            container,
            text="📋 Copy to Clipboard",
            command=self._copy_password,
            bootstyle=INFO,
            width=40
        ).pack(pady=(0, 20))
        
        # Options frame
        options_frame = ttk.LabelFrame(
            container,
            text="  Options  ",
            padding=15
        )
        options_frame.pack(fill=X, pady=(0, 20))
        
        # Length slider
        length_frame = ttk.Frame(options_frame)
        length_frame.pack(fill=X, pady=10)
        
        ttk.Label(
            length_frame,
            text="Length:",
            font=("Segoe UI", 10)
        ).pack(side=LEFT, padx=(0, 10))
        
        self.length_var = ttk.IntVar(value=16)
        
        length_scale = ttk.Scale(
            length_frame,
            from_=8,
            to=32,
            variable=self.length_var,
            orient=HORIZONTAL,
            length=280,
            command=lambda e: self._update_length_label()
        )
        length_scale.pack(side=LEFT, padx=10)
        
        self.length_label = ttk.Label(
            length_frame,
            text="16",
            font=("Segoe UI", 10, "bold"),
            width=3
        )
        self.length_label.pack(side=LEFT, padx=(10, 0))
        
        # Character type checkboxes
        ttk.Separator(options_frame, orient=HORIZONTAL).pack(fill=X, pady=15)
        
        self.uppercase_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Uppercase Letters (A-Z)",
            variable=self.uppercase_var,
            bootstyle=(SUCCESS, ROUND, TOGGLE)
        ).pack(fill=X, pady=5)
        
        self.lowercase_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Lowercase Letters (a-z)",
            variable=self.lowercase_var,
            bootstyle=(SUCCESS, ROUND, TOGGLE)
        ).pack(fill=X, pady=5)
        
        self.digits_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Digits (0-9)",
            variable=self.digits_var,
            bootstyle=(SUCCESS, ROUND, TOGGLE)
        ).pack(fill=X, pady=5)
        
        self.symbols_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Symbols (!@#$%...)",
            variable=self.symbols_var,
            bootstyle=(SUCCESS, ROUND, TOGGLE)
        ).pack(fill=X, pady=5)
        
        # Strength indicator
        strength_frame = ttk.Frame(container)
        strength_frame.pack(fill=X, pady=10)
        
        ttk.Label(
            strength_frame,
            text="Strength:",
            font=("Segoe UI", 10, "bold")
        ).pack(side=LEFT, padx=(0, 10))
        
        self.strength_label = ttk.Label(
            strength_frame,
            text="",
            font=("Segoe UI", 10, "bold")
        )
        self.strength_label.pack(side=LEFT, padx=(0, 15))
        
        self.strength_bar = ttk.Progressbar(
            strength_frame,
            length=250,
            mode=DETERMINATE,
            bootstyle=SUCCESS
        )
        self.strength_bar.pack(side=LEFT)
        
        # Buttons
        button_frame = ttk.Frame(container)
        button_frame.pack(fill=X, pady=15)
        
        ttk.Button(
            button_frame,
            text="🔄 Generate New",
            command=self._generate,
            bootstyle=PRIMARY,
            width=18
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Close",
            command=self.destroy,
            bootstyle=SECONDARY,
            width=18
        ).pack(side=LEFT, padx=5)
    
    def _update_length_label(self) -> None:
        """Update length display label."""
        self.length_label.config(text=str(self.length_var.get()))
    
    def _generate(self) -> None:
        """Generate a new password."""
        try:
            password = self.pm.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get()
            )
            
            # Display password
            self.password_display.config(state=NORMAL)
            self.password_display.delete(0, END)
            self.password_display.insert(0, password)
            self.password_display.config(state=READONLY)
            
            # Update strength indicator
            strength, score = PasswordGenerator.calculate_strength(password)
            self.strength_label.config(text=strength)
            self.strength_bar.config(value=score)
            
            # Color code strength
            if score < 40:
                self.strength_bar.config(bootstyle=DANGER)
                self.strength_label.config(bootstyle=DANGER)
            elif score < 60:
                self.strength_bar.config(bootstyle=WARNING)
                self.strength_label.config(bootstyle=WARNING)
            elif score < 80:
                self.strength_bar.config(bootstyle=INFO)
                self.strength_label.config(bootstyle=INFO)
            else:
                self.strength_bar.config(bootstyle=SUCCESS)
                self.strength_label.config(bootstyle=SUCCESS)
                
        except ValueError as e:
            Messagebox.show_error(
                str(e),
                "Generation Error",
                parent=self
            )
    
    def _copy_password(self) -> None:
        """Copy generated password to clipboard."""
        password = self.password_display.get()
        if password:
            pyperclip.copy(password)
            Messagebox.show_info(
                "Password copied to clipboard!",
                "Copied",
                parent=self,
                alert=True
            )
