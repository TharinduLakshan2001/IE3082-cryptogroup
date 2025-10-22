# IE3082-Crypto-Toolkit

**🔐 Advanced Encryption & Security Tools - Version 1.0**

A comprehensive command-line toolkit for cryptographic operations, designed for educational and practical use in security analysis and testing. It provides implementations and benchmarks for common symmetric, asymmetric, and hashing algorithms.

---

## Table of Contents

*   [Features](#features)
*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [Usage](#usage)
    *   [Main Commands](#main-commands)
    *   [Symmetric Encryption (AES)](#symmetric-encryption-aes)
    *   [Asymmetric Encryption (RSA)](#asymmetric-encryption-rsa)
    *   [Asymmetric Encryption (ECC)](#asymmetric-encryption-ecc)
    *   [Hashing (SHA-256)](#hashing-sha-256)
    *   [Benchmarking](#benchmarking)
    *   [One-Shot Encryption/Decryption](#one-shot-encryptiondecryption)
*   [Examples](#examples)
*   [Directory Structure](#directory-structure)
*   [Contributing](#contributing)
*   [License](#license)
*   [Author](#author)

---

## Features

*   **Symmetric Encryption:** AES-256-GCM (with support for 128-bit and 192-bit keys) for fast, authenticated encryption.
*   **Asymmetric Encryption:**
    *   RSA-3072 for key exchange and encryption (uses OAEP padding).
    *   Elliptic Curve Cryptography (ECC) using Curve25519 for key exchange and Ed25519 for digital signatures.
*   **Hashing:** SHA-256 for secure one-way hashing.
*   **Benchmarking:** Performance analysis for encryption, decryption, signing, and hashing operations.
*   **Integrated Benchmarking:** Compare performance of different algorithms on a single file.
*   **One-Shot Encryption/Decryption:** Simplified command for encrypting/decrypting a file with a generated key.
*   **File Handling:** Designed to work with various file types and sizes (with chunked processing for large files).

---

## Prerequisites

*   **Operating System:** Kali Linux (recommended) or a compatible Linux distribution.
*   **Python:** Version 3.6 or higher.
*   **Dependencies:** See the `requirements.txt` file for a list of required Python packages.

---

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/IE3082-Crypto-Toolkit.git
    cd IE3082-Crypto-Toolkit
    ```

2.  **Install Dependencies:**
    It's highly recommended to use a virtual environment:
    ```bash
    # Create a virtual environment (optional but recommended)
    python3 -m venv venv
    source venv/bin/activate # Activate the virtual environment

    # Install dependencies
    python3 install.py
    ```
    *Note: The `install.py` script attempts to handle dependencies using `pip`, `pip --break-system-packages` (for Kali/Linux post-PEP 668), and as a fallback, `apt` for common packages like `python3-cryptography`.*

3.  **Make Executable (Optional, for system-wide use):**
    Ensure `cryp.py` is executable:
    ```bash
    chmod +x cryp.py
    ```
    To make the `cryp` command available system-wide, the `install.py` script attempts to create a symlink in `/usr/local/bin`. If this fails, you can run the tool directly using `python3 cryp.py`.

---

## Usage

The toolkit is operated via the `cryp` command-line interface. Run `cryp -h` or `python3 cryp.py -h` for general help.

### Main Commands

*   `cryp aes <subcommand> ...`: For AES encryption/decryption and key generation.
*   `cryp rsa <subcommand> ...`: For RSA encryption/decryption, signing, verification, and key generation.
*   `cryp ecc <subcommand> ...`: For ECC key exchange, signing, verification, and key generation.
*   `cryp hash <subcommand> ...`: For SHA-256 hashing and verification.
*   `cryp bench <subcommand>`: For performance benchmarking.
*   `cryp ini <subcommand> <file>`: For integrated benchmarking or one-shot encryption/decryption.
*   `cryp -h`, `cryp --help`: Display help information.

### Symmetric Encryption (AES)

*   **Generate a Key:**
    ```bash
    cryp aes generate-key <key_file>
    ```
    *   `<key_file>`: Path to save the generated AES key (binary file).

*   **Encrypt a File:**
    ```bash
    cryp aes encrypt <input_file> <key_file> <nonce_file> <output_file>
    ```
    *   `<input_file>`: Path to the file to encrypt.
    *   `<key_file>`: Path to the AES key file (binary).
    *   `<nonce_file>`: Path to the nonce file (binary). If it doesn't exist, a new nonce will be generated and saved here.
    *   `<output_file>`: Path to save the encrypted file.

*   **Decrypt a File:**
    ```bash
    cryp aes decrypt <input_file> <key_file> <nonce_file> <output_file>
    ```
    *   `<input_file>`: Path to the encrypted file.
    *   `<key_file>`: Path to the AES key file (binary) used for encryption.
    *   `<nonce_file>`: Path to the nonce file (binary) used for encryption.
    *   `<output_file>`: Path to save the decrypted file.

*   **Demo:**
    ```bash
    cryp aes demo
    ```

### Asymmetric Encryption (RSA)

*   **Generate Keys:**
    ```bash
    cryp rsa generate-keys <private_key_file> <public_key_file>
    ```
    *   `<private_key_file>`: Path to save the private key (PEM format).
    *   `<public_key_file>`: Path to save the public key (PEM format).

*   **Encrypt (for small data):**
    ```bash
    cryp rsa encrypt <plaintext_file> <public_key_file> <output_file>
    ```
    *   `<plaintext_file>`: Path to the small file to encrypt (RSA has size limitations).
    *   `<public_key_file>`: Path to the recipient's public key (PEM format).
    *   `<output_file>`: Path to save the encrypted data.

*   **Decrypt:**
    ```bash
    cryp rsa decrypt <ciphertext_file> <private_key_file> <output_file>
    ```
    *   `<ciphertext_file>`: Path to the encrypted data.
    *   `<private_key_file>`: Path to the recipient's private key (PEM format).
    *   `<output_file>`: Path to save the decrypted data.

*   **Sign:**
    ```bash
    cryp rsa sign <message_file> <private_key_file> <signature_file>
    ```
    *   `<message_file>`: Path to the file to sign.
    *   `<private_key_file>`: Path to the signer's private key (PEM format).
    *   `<signature_file>`: Path to save the signature.

*   **Verify:**
    ```bash
    cryp rsa verify <message_file> <signature_file> <public_key_file>
    ```
    *   `<message_file>`: Path to the original file.
    *   `<signature_file>`: Path to the signature file.
    *   `<public_key_file>`: Path to the signer's public key (PEM format).

*   **Demo:**
    ```bash
    cryp rsa demo
    ```

### Asymmetric Encryption (ECC)

*   **Generate Keys (X25519/Ed25519):**
    ```bash
    cryp ecc generate-keys <private_key_file> <public_key_file>
    ```
    *   `<private_key_file>`: Path to save the private key (binary/Raw format).
    *   `<public_key_file>`: Path to save the public key (binary/Raw format).

*   **Key Exchange (X25519):**
    ```bash
    cryp ecc key-exchange <private_key_file> <peer_public_key_file> <shared_secret_file>
    ```
    *   `<private_key_file>`: Path to your private key (binary/Raw format).
    *   `<peer_public_key_file>`: Path to the other party's public key (binary/Raw format).
    *   `<shared_secret_file>`: Path to save the generated shared secret (binary).

*   **Sign (Ed25519):**
    ```bash
    cryp ecc sign <message_file> <private_key_file> <signature_file>
    ```
    *   `<message_file>`: Path to the file to sign.
    *   `<private_key_file>`: Path to the signer's private key (binary/Raw format).
    *   `<signature_file>`: Path to save the signature.

*   **Verify (Ed25519):**
    ```bash
    cryp ecc verify <message_file> <signature_file> <public_key_file>
    ```
    *   `<message_file>`: Path to the original file.
    *   `<signature_file>`: Path to the signature file.
    *   `<public_key_file>`: Path to the signer's public key (binary/Raw format).

*   **Demo:**
    ```bash
    cryp ecc demo
    ```

### Hashing (SHA-256)

*   **Hash a File:**
    ```bash
    cryp hash file <input_file>
    ```
    *   `<input_file>`: Path to the file to hash.

*   **Hash Text:**
    ```bash
    cryp hash text <input_text>
    ```
    *   `<input_text>`: The text string to hash.

*   **Verify File Hash:**
    ```bash
    cryp hash verify <input_file> <expected_hash>
    ```
    *   `<input_file>`: Path to the file to verify.
    *   `<expected_hash>`: The expected SHA-256 hash string.

*   **Demo:**
    ```bash
    cryp hash demo
    ```

### Benchmarking

*   **Run Encryption Benchmark:**
    ```bash
    cryp bench encryption
    ```
    Benchmarks AES, RSA, and ECC performance.

*   **Run Hashing Benchmark:**
    ```bash
    cryp bench hashing
    ```
    Benchmarks SHA-256 performance.

*   **Run Demo Benchmark:**
    ```bash
    cryp bench demo
    ```

*   **Run Integrated Encryption Benchmark:**
    ```bash
    cryp ini en <input_file>
    ```
    *   `<input_file>`: The file to benchmark.
    Prompts for AES key size and compares performance of AES, RSA (hybrid), ECC (signing), and SHA-256 on this specific file. Results are saved in a folder named `<input_file>_en`.

*   **Run Integrated Decryption Benchmark:**
    ```bash
    cryp ini de <input_file>
    ```
    *   `<input_file>`: The original file used with `ini en`. It expects the `<input_file>_en` directory to exist.
    Benchmarks the decryption/verification processes corresponding to the `ini en` run.

### One-Shot Encryption/Decryption

*   **Encrypt a File:**
    ```bash
    cryp ini en ones <input_file>
    ```
    *   `<input_file>`: The file to encrypt.
    Prompts for AES key size, generates a key and nonce, encrypts the file, and saves the encrypted file, key, and nonce in a folder named `<input_file>_encrypted`. Provides instructions for sharing and decryption.

*   **Decrypt a File:**
    ```bash
    cryp ini de ones <encrypted_file>
    ```
    *   `<encrypted_file>`: The encrypted file (e.g., `document.pdf.enc`).
    Looks for the associated `key.bin` and `nonce.bin` files in the same directory as the encrypted file and decrypts it, saving the result as `<encrypted_file_name>_decrypted`.

---

## Examples

1.  **Encrypt a file using AES:**
    ```bash
    # Generate a key
    cryp aes generate-key my_secret.key
    # Encrypt the file
    cryp aes encrypt document.pdf my_secret.key nonce.bin document_encrypted.aes
    ```

2.  **Run a simple benchmark:**
    ```bash
    cryp bench demo
    ```

3.  **Encrypt a file using the one-shot command:**
    ```bash
    cryp ini en ones secret_document.pdf
    # Follow the prompts. The encrypted file and key will be in secret_document_encrypted/
    ```

4.  **Decrypt the file from the one-shot example:**
    ```bash
    cryp ini de ones secret_document_encrypted/secret_document.pdf.enc
    # The decrypted file will be saved in the same directory as the encrypted file.
    ```

---

## Directory Structure


Benchmark results are exported as CSV files and graphical plots for analysis.

## 🎨 Colorful Output

The toolkit features colorful, user-friendly output for better experience:
- Cyan headers for clear section identification
- Green success messages
- Red error messages
- Yellow warnings
- Blue informational messages

## 🧰 Requirements

- Python 3.6+
- cryptography library
- matplotlib (for benchmarking graphs)

These are automatically installed by the installation script.

## 🔒 Security Notes

- Keys are generated using cryptographically secure random number generators
- AES-256-GCM provides authenticated encryption
- RSA-3072 offers strong asymmetric encryption
- ECC Curve25519 provides efficient asymmetric operations
- SHA-256 is a secure hashing algorithm

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built for IE3082 Cryptography and Network Security course
- Uses the Python cryptography library

- Designed for Kali Linux environment

