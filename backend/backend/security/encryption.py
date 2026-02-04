"""
Encrypted Storage

Provides encryption layer for sensitive data at rest using Fernet (AES-128 CBC).
Keys should be stored in environment variables, never hardcoded.
"""

import os
import json
from typing import Dict, Any
from cryptography.fernet import Fernet

class EncryptedStorage:
    """Handle encryption/decryption of sensitive log data"""
    
    # Fields that should always be encrypted
    ALWAYS_ENCRYPT = {
        'password', 'passwd', 'pwd', 'pass',
        'token', 'api_key', 'secret', 'jwt',
        'ssn', 'credit_card', 'card_number',
        'private_key', 'auth_token'
    }
    
    def __init__(self, encryption_key: str = None):
        """
        Initialize encryption with key from environment
        
        Args:
            encryption_key: Base64-encoded Fernet key. If None, reads from env var PHOSOR_ENCRYPTION_KEY
        """
        if encryption_key is None:
            encryption_key = os.getenv('PHOSOR_ENCRYPTION_KEY')
        
        if encryption_key is None:
            # Generate new key and warn
            key = Fernet.generate_key()
            print("[SECURITY WARNING] No encryption key found!")
            print(f"[SECURITY WARNING] Generated new key: {key.decode()}")
            print("[SECURITY WARNING] Set PHOSOR_ENCRYPTION_KEY environment variable to persist!")
            self.cipher = Fernet(key)
            self.key_warning_shown = True
        else:
            try:
                if isinstance(encryption_key, str):
                    encryption_key = encryption_key.encode()
                self.cipher = Fernet(encryption_key)
                self.key_warning_shown = False
            except Exception as e:
                raise ValueError(f"Invalid encryption key: {e}")
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt a string
        
        Returns:
            Base64-encoded encrypted data
        """
        if not data:
            return data
        
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            print(f"[ENCRYPTION ERROR] Failed to encrypt data: {e}")
            return data  # Return original if encryption fails
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt a string
        
        Returns:
            Decrypted plaintext
        """
        if not encrypted_data:
            return encrypted_data
        
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            print(f"[DECRYPTION ERROR] Failed to decrypt data: {e}")
            return encrypted_data  # Return as-is if decryption fails
    
    def encrypt_dict(self, data: Dict[str, Any], fields_to_encrypt: set = None) -> Dict[str, Any]:
        """
        Encrypt specific fields in a dictionary
        
        Args:
            data: Dictionary to process
            fields_to_encrypt: Set of field names to encrypt (defaults to ALWAYS_ENCRYPT)
        
        Returns:
            Dictionary with encrypted fields
        """
        if fields_to_encrypt is None:
            fields_to_encrypt = self.ALWAYS_ENCRYPT
        
        encrypted = {}
        for key, value in data.items():
            if key.lower() in fields_to_encrypt:
                # Encrypt this field
                if isinstance(value, str):
                    encrypted[key] = self.encrypt(value)
                else:
                    # Convert to JSON first
                    encrypted[key] = self.encrypt(json.dumps(value))
            else:
                encrypted[key] = value
        
        return encrypted
    
    def decrypt_dict(self, data: Dict[str, Any], fields_to_decrypt: set = None) -> Dict[str, Any]:
        """
        Decrypt specific fields in a dictionary
        
        Args:
            data: Dictionary with encrypted fields
            fields_to_decrypt: Set of field names to decrypt (defaults to ALWAYS_ENCRYPT)
        
        Returns:
            Dictionary with decrypted fields
        """
        if fields_to_decrypt is None:
            fields_to_decrypt = self.ALWAYS_ENCRYPT
        
        decrypted = {}
        for key, value in data.items():
            if key.lower() in fields_to_decrypt and isinstance(value, str):
                try:
                    decrypted[key] = self.decrypt(value)
                except:
                    decrypted[key] = value  # Keep original if decryption fails
            else:
                decrypted[key] = value
        
        return decrypted
    
    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key
        
        Returns:
            Base64-encoded key string
        """
        return Fernet.generate_key().decode()
    
    def is_encrypted(self, data: str) -> bool:
        """
        Check if data appears to be encrypted (Fernet format check)
        
        Returns:
            True if data looks like Fernet-encrypted data
        """
        try:
            # Fernet tokens are base64 and start with 'gAAAAA'
            return data.startswith('gAAAAA') if data else False
        except:
            return False
