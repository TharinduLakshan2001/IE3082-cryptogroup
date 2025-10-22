#!/usr/bin/env python3
"""
AES-GCM Symmetric Encryption Module for IE3082-Crypto-Toolkit

Provides file encryption/decryption with AES-GCM and key generation with configurable key sizes.
Features chunked processing for handling large files efficiently.
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag # Import specific exception


def generate_aes_key(key_size=32):
    """
    Generate an AES key of specified size.

    Args:
        key_size (int): Size of the key in bytes (16=128-bit, 24=192-bit, 32=256-bit)

    Returns:
        bytes: AES key of specified size

    Raises:
        ValueError: If key_size is not 16, 24, or 32.
    """
    if key_size not in [16, 24, 32]:
        raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
    return secrets.token_bytes(key_size)


def encrypt_file_aes(input_file, key, nonce, output_file, chunk_size=8192):
    """
    Encrypt a file using AES-GCM with chunked processing.

    Args:
        input_file (str): Path to the input file to encrypt
        key (bytes): AES key (16, 24, or 32 bytes)
        nonce (bytes): 12-byte nonce for GCM
        output_file (str): Path to the output encrypted file
        chunk_size (int): Size of data chunks to process at a time (default 8192 bytes)

    Returns:
        bytes: Authentication tag (16 bytes)

    Raises:
        ValueError: If key or nonce have incorrect lengths.
        FileNotFoundError: If input_file does not exist.
        IOError: If there's an issue reading the input or writing the output file.
    """
    # Validate inputs
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM mode")

    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Process the input file in chunks and write encrypted chunks to the output file
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        while True:
            chunk = infile.read(chunk_size)
            if len(chunk) == 0:
                break
            encrypted_chunk = encryptor.update(chunk)
            outfile.write(encrypted_chunk)

        # Finalize encryption and get the tag
        final_encrypted_part = encryptor.finalize()
        tag = encryptor.tag

        # Write the final part (often empty for GCM) and the tag to the output file
        outfile.write(final_encrypted_part)
        outfile.write(tag)

    return tag


def decrypt_file_aes(input_file, key, nonce, output_file, chunk_size=8192):
    """
    Decrypt a file using AES-GCM and verify integrity with chunked processing.

    Args:
        input_file (str): Path to the input encrypted file
        key (bytes): AES key (16, 24, or 32 bytes)
        nonce (bytes): 12-byte nonce for GCM
        output_file (str): Path to the output decrypted file
        chunk_size (int): Size of data chunks to process at a time (default 8192 bytes)

    Returns:
        bool: True if decryption and verification succeeded

    Raises:
        ValueError: If key or nonce have incorrect lengths, or if decryption fails.
        FileNotFoundError: If input_file does not exist.
        IOError: If there's an issue reading the input or writing the output file.
    """
    # Validate inputs
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM mode")

    # Read the input file to extract ciphertext and tag
    with open(input_file, 'rb') as f:
        data = f.read()

    # Extract ciphertext and tag
    if len(data) < 16:
        raise ValueError("Input file is too small to contain valid AES-GCM data (ciphertext + tag)")
    ciphertext = data[:-16]  # Everything except last 16 bytes
    tag = data[-16:]         # Last 16 bytes is the tag

    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag), # Provide the tag for verification here
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Process the ciphertext in chunks and write decrypted chunks to the output file
    with open(output_file, 'wb') as outfile:
        # Decrypt the main ciphertext part in chunks
        start_idx = 0
        while start_idx < len(ciphertext):
            end_idx = min(start_idx + chunk_size, len(ciphertext))
            chunk = ciphertext[start_idx:end_idx]
            decrypted_chunk = decryptor.update(chunk)
            outfile.write(decrypted_chunk)
            start_idx = end_idx

        # Finalize decryption (verification happens here)
        try:
            final_decrypted_part = decryptor.finalize() # This call verifies the tag
            outfile.write(final_decrypted_part)
        except InvalidTag:
            # Catch the specific exception for failed authentication
            raise ValueError("Decryption failed: Authentication tag verification failed.")

    # If we reach here, decryption and verification were successful
    return True


def aes_demo():
    """Demonstrate AES encryption and decryption with sample data."""
    print("[+] AES-256-GCM Demo Starting...")

    # Generate a 256-bit key and nonce
    key = generate_aes_key(32)  # 256-bit
    nonce = secrets.token_bytes(12)

    # Create a sample file
    sample_data = b"This is a sample file for AES encryption demonstration." + b" More data..." * 1000 # Make it larger to test chunking
    with open("sample.txt", "wb") as f:
        f.write(sample_data)

    print(f"[+] Original data (first 50 bytes): {sample_data[:50]}...")

    # Encrypt the file
    encrypt_file_aes("sample.txt", key, nonce, "sample_encrypted.bin")
    print("[+] File encrypted successfully.")

    # Decrypt the file
    try:
        success = decrypt_file_aes("sample_encrypted.bin", key, nonce, "sample_decrypted.txt")
        if success:
            print("[+] File decrypted successfully.")
        else:
            print("[-] Decryption reported failure.")
            return
    except ValueError as e:
        print(f"[-] Decryption failed: {e}")
        return

    # Read and verify the decrypted data
    with open("sample_decrypted.txt", "rb") as f:
        decrypted_data = f.read()

    print(f"[+] Decrypted data (first 50 bytes): {decrypted_data[:50]}...")

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
