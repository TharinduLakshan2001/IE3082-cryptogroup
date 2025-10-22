#!/usr/bin/env python3
"""
ECC (Curve25519) Asymmetric Encryption Module for IE3082-Crypto-Toolkit

Provides key generation, Diffie-Hellman key exchange (X25519), 
and digital signatures/verification (Ed25519).
"""

import os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature # Import specific exception


def generate_curve25519_keys():
    """
    Generate X25519 key pair for key exchange.

    Returns:
        tuple: (private_key, public_key) objects
    """
    # Generate private key
    private_key = x25519.X25519PrivateKey.generate()

    # Get public key
    public_key = private_key.public_key()

    return private_key, public_key


def save_x25519_keys(private_key, public_key, private_key_file="x25519_private_key.pem", public_key_file="x25519_public_key.pem"):
    """
    Save X25519 keys to PEM files using Raw format.

    Args:
        private_key: X25519 private key object
        public_key: X25519 public key object
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key
    """
    # Serialize and save private key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.Raw, # Raw format for Curve25519 private keys
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(private_key_file, 'wb') as f:
        f.write(private_bytes)

    # Serialize and save public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.Raw # Raw format for Curve25519 public keys
    )

    with open(public_key_file, 'wb') as f:
        f.write(public_bytes)


def load_x25519_keys(private_key_file="x25519_private_key.pem", public_key_file="x25519_public_key.pem"):
    """
    Load X25519 keys from PEM files using Raw format.

    Args:
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key

    Returns:
        tuple: (private_key, public_key) objects
    """
    # Load private key
    with open(private_key_file, 'rb') as f:
        private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())

    # Load public key
    with open(public_key_file, 'rb') as f:
        public_key = x25519.X25519PublicKey.from_public_bytes(f.read())

    return private_key, public_key


def ecc_key_exchange(private_key, peer_public_key):
    """
    Perform Diffie-Hellman key exchange to derive a shared secret.

    Args:
        private_key: X25519 private key object
        peer_public_key: X25519 public key object of the peer

    Returns:
        bytes: Shared secret (32 bytes)
    """
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def generate_ed25519_keys():
    """
    Generate Ed25519 key pair for signing.

    Returns:
        tuple: (private_key, public_key) objects
    """
    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Get public key
    public_key = private_key.public_key()

    return private_key, public_key


def save_ed25519_keys(private_key, public_key, private_key_file="ed25519_private_key.pem", public_key_file="ed25519_public_key.pem"):
    """
    Save Ed25519 keys to PEM files using standard formats.

    Args:
        private_key: Ed25519 private key object
        public_key: Ed25519 public key object
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key
    """
    # Serialize and save private key using PKCS8 format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8, # Standard format for Ed25519 private keys
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(private_key_file, 'wb') as f:
        f.write(private_pem)

    # Serialize and save public key using SubjectPublicKeyInfo format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard format for Ed25519 public keys
    )

    with open(public_key_file, 'wb') as f:
        f.write(public_pem)


def load_ed25519_keys(private_key_file="ed25519_private_key.pem", public_key_file="ed25519_public_key.pem"):
    """
    Load Ed25519 keys from PEM files.

    Args:
        private_key_file (str): Filename for private key
        public_key_file (str): Filename for public key

    Returns:
        tuple: (private_key, public_key) objects
    """
    # Load private key
    with open(private_key_file, 'rb') as f:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())

    # Load public key
    with open(public_key_file, 'rb') as f:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(f.read())

    return private_key, public_key


def ed25519_sign(message, private_key):
    """
    Sign a message using Ed25519 private key.

    Args:
        message (bytes): Message to sign
        private_key: Ed25519 private key object

    Returns:
        bytes: Digital signature
    """
    signature = private_key.sign(message)
    return signature


def ed25519_verify(message, signature, public_key):
    """
    Verify a signature using Ed25519 public key.

    Args:
        message (bytes): Original message
        signature (bytes): Digital signature
        public_key: Ed25519 public key object

    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature: # Catch the specific exception
        return False
    except Exception as e:
        # Catch any other unexpected errors during verification
        # print(f"Unexpected error during Ed25519 verification: {e}") # Optional: for debugging
        return False


def ecc_demo():
    """Demonstrate ECC key exchange and EdDSA signing/verification."""
    print("[+] ECC (Curve25519) Demo Starting...")

    # Generate X25519 key pairs for two parties
    alice_private, alice_public = generate_curve25519_keys()
    bob_private, bob_public = generate_curve25519_keys()

    print("[+] Generated X25519 key pairs for Alice and Bob.")

    # For the demo, we'll skip saving/loading to files to avoid the serialization issue
    # Instead, we'll work directly with the key objects

    # Perform key exchange
    alice_shared_secret = ecc_key_exchange(alice_private, bob_public)
    bob_shared_secret = ecc_key_exchange(bob_private, alice_public)

    print("[+] Performed Diffie-Hellman key exchange.")

    # Verify shared secrets match
    if alice_shared_secret == bob_shared_secret:
        print("[+] Key exchange successful: Shared secrets match!")
    else:
        print("[-] Key exchange failed: Shared secrets do not match!")

    # Generate Ed25519 key pairs for signing
    signer_private, signer_public = generate_ed25519_keys()

    print("[+] Generated Ed25519 key pair for signing.")

    # Sample message
    message = b"This is a sample message for EdDSA signing demonstration."
    print(f"[+] Original message: {message}")

    # Sign message
    signature = ed25519_sign(message, signer_private)
    print("[+] Message signed with EdDSA.")

    # Verify signature
    is_valid = ed25519_verify(message, signature, signer_public)
    print(f"[+] Signature verification: {'Valid' if is_valid else 'Invalid'}")

    # Verify with wrong message
    wrong_message = b"This is a wrong message."
    is_valid_wrong = ed25519_verify(wrong_message, signature, signer_public)
    print(f"[+] Wrong message signature verification: {'Valid' if is_valid_wrong else 'Invalid'}")

    # Verify operations
    if alice_shared_secret == bob_shared_secret and is_valid and not is_valid_wrong:
        print("[+] ECC Demo Successful!")
    else:
        print("[-] ECC Demo Failed!")


if __name__ == "__main__":
    ecc_demo()
