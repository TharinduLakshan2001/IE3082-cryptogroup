#!/usr/bin/env python3
"""
SHA-256 Hashing Module for IE3082-Crypto-Toolkit

Provides file and text hashing, and hash verification functions.
Features chunked processing for handling large files efficiently.
"""

import hashlib
import os


def hash_file_sha256(input_file):
    """
    Generate SHA-256 hash of a file using chunked processing.

    Args:
        input_file (str): Path to the input file

    Returns:
        str: SHA-256 hash in hexadecimal format

    Raises:
        FileNotFoundError: If input_file does not exist.
        IOError: If there's an issue reading the input file.
    """
    sha256_hash = hashlib.sha256()

    with open(input_file, "rb") as f:
        # Read and update hash in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def hash_text_sha256(input_string):
    """
    Generate SHA-256 hash of a text string.

    Args:
        input_string (str or bytes): Input text to hash

    Returns:
        str: SHA-256 hash in hexadecimal format
    """
    if isinstance(input_string, str):
        input_string = input_string.encode('utf-8')

    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string)
    return sha256_hash.hexdigest()


def verify_file_hash(input_file, expected_hash):
    """
    Verify the SHA-256 hash of a file against an expected hash.

    Args:
        input_file (str): Path to the input file
        expected_hash (str): Expected SHA-256 hash in hexadecimal format

    Returns:
        bool: True if hashes match, False otherwise

    Raises:
        FileNotFoundError: If input_file does not exist.
        IOError: If there's an issue reading the input file.
    """
    actual_hash = hash_file_sha256(input_file)
    # Perform case-insensitive comparison for user-friendliness
    return actual_hash.lower() == expected_hash.lower()


def hash_demo():
    """Demonstrate SHA-256 hashing functionality."""
    print("[+] SHA-256 Hashing Demo Starting...")

    # Create sample files
    sample_text = "This is a sample text for SHA-256 hashing demonstration."
    with open("sample_text.txt", "w") as f:
        f.write(sample_text)

    sample_binary = b"This is sample binary data\x00\x01\x02\x03"
    with open("sample_binary.bin", "wb") as f:
        f.write(sample_binary)

    print(f"[+] Created sample text file with content: {sample_text}")
    print(f"[+] Created sample binary file with {len(sample_binary)} bytes")

    # Hash text
    text_hash = hash_text_sha256(sample_text)
    print(f"[+] SHA-256 hash of text: {text_hash}")

    # Hash files
    text_file_hash = hash_file_sha256("sample_text.txt")
    binary_file_hash = hash_file_sha256("sample_binary.bin")

    print(f"[+] SHA-256 hash of text file: {text_file_hash}")
    print(f"[+] SHA-256 hash of binary file: {binary_file_hash}")

    # Verify hashes
    text_verified = verify_file_hash("sample_text.txt", text_file_hash)
    binary_verified = verify_file_hash("sample_binary.bin", binary_file_hash)
    wrong_verified = verify_file_hash("sample_text.txt", "0" * 64)  # Wrong hash

    print(f"[+] Text file hash verification: {'Passed' if text_verified else 'Failed'}")
    print(f"[+] Binary file hash verification: {'Passed' if binary_verified else 'Failed'}")
    print(f"[+] Wrong hash verification: {'Passed' if wrong_verified else 'Failed'}")

    # Clean up sample files
    os.remove("sample_text.txt")
    os.remove("sample_binary.bin")

    # Verify operations
    if text_hash == text_file_hash and text_verified and binary_verified and not wrong_verified:
        print("[+] SHA-256 Hashing Demo Successful!")
    else:
        print("[-] SHA-256 Hashing Demo Failed!")


if __name__ == "__main__":
    hash_demo()
