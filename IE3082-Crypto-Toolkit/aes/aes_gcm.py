"""
AES-256-GCM Symmetric Encryption Module for IE3082-Crypto-Toolkit
Provides file encryption/decryption with AES-256-GCM and key generation.
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    """Generate a 256-bit (32 bytes) AES key."""
    return secrets.token_bytes(32)

def encrypt_file_aes(input_file, key, nonce, output_file):
    """
    Encrypt a file using AES-256-GCM.
    
    Args:
        input_file (str): Path to the input file to encrypt
        key (bytes): 32-byte AES key
        nonce (bytes): 12-byte nonce for GCM
        output_file (str): Path to the output encrypted file
    
    Returns:
        bytes: Authentication tag (16 bytes)
    """
    # Validate inputs
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM mode")
    
    # Read the input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # Write the encrypted data and tag to output file
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
        f.write(tag)
    
    return tag

def decrypt_file_aes(input_file, key, nonce, output_file):
    """
    Decrypt a file using AES-256-GCM and verify integrity.
    
    Args:
        input_file (str): Path to the input encrypted file
        key (bytes): 32-byte AES key
        nonce (bytes): 12-byte nonce for GCM
        output_file (str): Path to the output decrypted file
    
    Returns:
        bool: True if decryption and verification succeeded
    """
    # Validate inputs
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM mode")
    
    # Read the input file
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Extract ciphertext and tag
    ciphertext = data[:-16]  # Everything except last 16 bytes
    tag = data[-16:]         # Last 16 bytes is the tag
    
    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Write the decrypted data to output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
            
        return True
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def aes_demo():
    """Demonstrate AES encryption and decryption with sample data."""
    print("[+] AES-256-GCM Demo Starting...")
    
    # Generate a key and nonce
    key = generate_aes_key()
    nonce = secrets.token_bytes(12)
    
    # Create a sample file
    sample_data = b"This is a sample file for AES encryption demonstration."
    with open("sample.txt", "wb") as f:
        f.write(sample_data)
    
    print(f"[+] Original data: {sample_data}")
    
    # Encrypt the file
    encrypt_file_aes("sample.txt", key, nonce, "sample_encrypted.bin")
    print("[+] File encrypted successfully.")
    
    # Decrypt the file
    decrypt_file_aes("sample_encrypted.bin", key, nonce, "sample_decrypted.txt")
    
    # Read and verify the decrypted data
    with open("sample_decrypted.txt", "rb") as f:
        decrypted_data = f.read()
    
    print(f"[+] Decrypted data: {decrypted_data}")
    
    # Verify integrity
    if sample_data == decrypted_data:
        print("[+] AES Demo Successful: Data integrity verified!")
    else:
        print("[-] AES Demo Failed: Data mismatch!")
    
    # Clean up temporary files
    os.remove("sample.txt")
    os.remove("sample_encrypted.bin")
    os.remove("sample_decrypted.txt")

if __name__ == "__main__":
    aes_demo()