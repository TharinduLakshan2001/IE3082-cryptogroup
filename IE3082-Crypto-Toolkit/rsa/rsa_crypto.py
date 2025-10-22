#!/usr/bin/env python3
"""
RSA-3072 Asymmetric Encryption Module for IE3082-Crypto-Toolkit

Provides RSA key generation, encryption, decryption, signing, and verification.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature # Import specific exception


def generate_rsa_keys():
    """
    Generate RSA-3072 key pair.

    Returns:
        tuple: (private_key, public_key) objects
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )

    # Get public key
    public_key = private_key.public_key()

    return private_key, public_key


def save_rsa_keys(private_key, public_key, private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """
    Save RSA keys to PEM files using standard formats.

    Args:
        private_key: RSA private key object
        public_key: RSA public key object
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key
    """
    # Serialize and save private key using PKCS8 format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(private_key_file, 'wb') as f:
        f.write(private_pem)

    # Serialize and save public key using SubjectPublicKeyInfo format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(public_key_file, 'wb') as f:
        f.write(public_pem)


def load_rsa_keys(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """
    Load RSA keys from PEM files.

    Args:
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key

    Returns:
        tuple: (private_key, public_key) objects

    Raises:
        FileNotFoundError: If the specified key files do not exist.
        ValueError: If the key files contain invalid data.
    """
    # Load private key
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Load public key
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    return private_key, public_key


def rsa_encrypt(plaintext, public_key):
    """
    Encrypt a message using RSA public key with OAEP padding.

    Args:
        plaintext (bytes): Message to encrypt (must be smaller than key size - padding overhead)
        public_key: RSA public key object

    Returns:
        bytes: Encrypted ciphertext

    Raises:
        ValueError: If plaintext is too large for the key size and padding.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    """
    Decrypt a message using RSA private key with OAEP padding.

    Args:
        ciphertext (bytes): Encrypted message
        private_key: RSA private key object

    Returns:
        bytes: Decrypted plaintext

    Raises:
        ValueError: If decryption fails (e.g., invalid padding or ciphertext).
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def rsa_sign(message, private_key):
    """
    Sign a message using RSA private key with PSS padding.

    Args:
        message (bytes): Message to sign
        private_key: RSA private key object

    Returns:
        bytes: Digital signature
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify(message, signature, public_key):
    """
    Verify a signature using RSA public key with PSS padding.

    Args:
        message (bytes): Original message
        signature (bytes): Digital signature
        public_key: RSA public key object

    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature: # Catch the specific exception
        return False
    except Exception as e:
        # Catch any other unexpected errors during verification
        # print(f"Unexpected error during RSA verification: {e}") # Optional: for debugging
        return False


def rsa_demo():
    """Demonstrate RSA encryption, decryption, signing, and verification."""
    print("[+] RSA-3072 Demo Starting...")

    # Generate key pair
    private_key, public_key = generate_rsa_keys()
    print("[+] RSA key pair generated.")

    # Save keys to files
    save_rsa_keys(private_key, public_key)
    print("[+] RSA keys saved to files.")

    # Sample message (must be small enough for RSA-3072 OAEP)
    message = b"This is a sample message for RSA encryption and signing demonstration."
    print(f"[+] Original message: {message}")

    # Encrypt message
    try:
        ciphertext = rsa_encrypt(message, public_key)
        print("[+] Message encrypted.")
    except ValueError as e:
        print(f"[-] Encryption failed: {e}")
        return

    # Decrypt message
    try:
        decrypted_message = rsa_decrypt(ciphertext, private_key)
        print(f"[+] Decrypted message: {decrypted_message}")
    except ValueError as e:
        print(f"[-] Decryption failed: {e}")
        return

    # Sign message
    signature = rsa_sign(message, private_key)
    print("[+] Message signed.")

    # Verify signature
    is_valid = rsa_verify(message, signature, public_key)
    print(f"[+] Signature verification: {'Valid' if is_valid else 'Invalid'}")

    # Verify with wrong message
    wrong_message = b"This is a wrong message."
    is_valid_wrong = rsa_verify(wrong_message, signature, public_key)
    print(f"[+] Wrong message signature verification: {'Valid' if is_valid_wrong else 'Invalid'}")

    # Clean up key files
    os.remove("private_key.pem")
    os.remove("public_key.pem")

    # Verify operations
    if message == decrypted_message and is_valid and not is_valid_wrong:
        print("[+] RSA Demo Successful!")
    else:
        print("[-] RSA Demo Failed!")


if __name__ == "__main__":
    rsa_demo()
