"""
Encryption utilities for secure credential storage
"""
from cryptography.fernet import Fernet
from shared.config import get_settings


def get_cipher() -> Fernet:
    """
    Get the Fernet cipher instance using the encryption key from settings
    """
    settings = get_settings()

    if not settings.encryption_key:
        raise ValueError(
            "ENCRYPTION_KEY is not set. Please run ./setup.sh to configure "
            "the application, or generate a key manually with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

    try:
        return Fernet(settings.encryption_key.encode())
    except ValueError:
        raise ValueError(
            "Invalid ENCRYPTION_KEY in .env file. The key must be a valid Fernet key "
            "(32 url-safe base64-encoded bytes). Please run ./setup.sh to generate a new key, "
            "or generate one manually with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )


def encrypt_password(password: str) -> bytes:
    """
    Encrypt a password using Fernet symmetric encryption

    Args:
        password: Plain text password to encrypt

    Returns:
        Encrypted password as bytes
    """
    cipher = get_cipher()
    return cipher.encrypt(password.encode())


def decrypt_password(encrypted_password: bytes) -> str:
    """
    Decrypt a password using Fernet symmetric encryption

    Args:
        encrypted_password: Encrypted password bytes

    Returns:
        Decrypted plain text password
    """
    cipher = get_cipher()
    return cipher.decrypt(encrypted_password).decode()


# Alias for API key encryption/decryption (same as password)
encrypt_api_key = encrypt_password
decrypt_api_key = decrypt_password


def generate_key() -> str:
    """
    Generate a new Fernet encryption key

    Returns:
        Base64-encoded encryption key as string
    """
    return Fernet.generate_key().decode()
