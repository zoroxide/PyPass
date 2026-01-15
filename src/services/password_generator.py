"""
Password generator module for creating secure random passwords.
"""

import secrets
import string
from typing import List


class PasswordGenerator:
    """
    Generates secure random passwords with configurable options.
    """
    
    @staticmethod
    def generate(
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Length of the password (minimum 4).
            use_uppercase: Include uppercase letters.
            use_lowercase: Include lowercase letters.
            use_digits: Include digits.
            use_symbols: Include special symbols.
            
        Returns:
            Generated password string.
            
        Raises:
            ValueError: If length < 4 or no character types selected.
        """
        if length < 4:
            raise ValueError("Password length must be at least 4")
        
        # Build character pool
        char_pool = ""
        required_chars: List[str] = []
        
        if use_uppercase:
            char_pool += string.ascii_uppercase
            required_chars.append(secrets.choice(string.ascii_uppercase))
        
        if use_lowercase:
            char_pool += string.ascii_lowercase
            required_chars.append(secrets.choice(string.ascii_lowercase))
        
        if use_digits:
            char_pool += string.digits
            required_chars.append(secrets.choice(string.digits))
        
        if use_symbols:
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            char_pool += symbols
            required_chars.append(secrets.choice(symbols))
        
        if not char_pool:
            raise ValueError("At least one character type must be selected")
        
        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [
            secrets.choice(char_pool) for _ in range(remaining_length)
        ]
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return "".join(password_chars)
    
    @staticmethod
    def calculate_strength(password: str) -> tuple[str, int]:
        """
        Calculate password strength.
        
        Args:
            password: Password to evaluate.
            
        Returns:
            Tuple of (strength_label, score) where:
            - strength_label: "Weak", "Medium", "Strong", or "Very Strong"
            - score: Strength score from 0-100
        """
        if not password:
            return "Weak", 0
        
        score = 0
        
        # Length contribution (up to 30 points)
        length = len(password)
        score += min(30, length * 2)
        
        # Character variety contribution (up to 40 points)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        variety_score = sum([has_lower, has_upper, has_digit, has_symbol]) * 10
        score += variety_score
        
        # Complexity contribution (up to 30 points)
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        if has_upper and has_lower and has_digit and has_symbol:
            score += 10
        
        # Determine strength label
        if score < 40:
            strength = "Weak"
        elif score < 60:
            strength = "Medium"
        elif score < 80:
            strength = "Strong"
        else:
            strength = "Very Strong"
        
        return strength, min(100, score)
