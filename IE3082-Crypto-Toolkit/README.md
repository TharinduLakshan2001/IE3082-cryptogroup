# IE3082-Crypto-Toolkit

**Advanced Kali Linux Encryption and Decryption Tool with AES-256-GCM, RSA-3072, ECC (Curve25519), and SHA-256.**

## 🛡️ Overview

IE3082-Crypto-Toolkit is a comprehensive cryptographic tool suite designed for Kali Linux. It provides implementations of industry-standard encryption algorithms with a user-friendly command-line interface. It includes core cryptographic operations, performance benchmarking, and a simplified one-shot encryption/decryption feature.

## 🚀 Features

### 1. Symmetric Encryption (AES-256-GCM)
- File encryption and decryption with AES-GCM (supporting 128, 192, 256-bit keys)
- Authenticated encryption with integrity verification
- Key and nonce generation
- Chunked processing for large files

### 2. Asymmetric Encryption (RSA-3072)
- RSA key pair generation (3072-bit)
- Message encryption and decryption (OAEP padding)
- Digital signatures and verification (PSS padding)

### 3. Asymmetric Encryption (ECC Curve25519/Ed25519)
- X25519 key pair generation and Diffie-Hellman key exchange
- Ed25519 key pair generation, digital signatures, and verification

### 4. Hashing (SHA-256)
- File hashing (chunked processing)
- Text hashing
- Hash verification

### 5. Performance Benchmarking
- Encryption/decryption performance testing for AES, RSA, ECC, SHA
- Hashing performance testing
- Integrated benchmarking comparing algorithms on a single file
- CSV result export
- Graphical result visualization

### 6. Simplified One-Shot Encryption/Decryption
- Encrypt a file with a generated key in one command: `cryp ini en ones <file>`
- Decrypt the file using the generated key/nonce: `cryp ini de ones <encrypted_file>`

## 📁 Project Structure

IE3082-Crypto-Toolkit/
├── aes/
│ └── aes_gcm.py # AES-GCM implementation
├── rsa/
│ └── rsa_crypto.py # RSA-3072 implementation
├── ecc/
│ └── ecc_crypto.py # ECC Curve25519/Ed25519 implementation
├── hashing/
│ └── sha256_hash.py # SHA-256 implementation
├── benchmark/
│ └── performance_bench.py # Benchmarking utilities
├── utils/
│ └── color_utils.py # Colorful output utilities
├── cryp.py # Main CLI interface
├── install.py # Installation script
├── requirements.txt # Python dependencies
└── README.md # This file


## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/TharinduLakshan2001/IE3082-cryptogroup.git
    cd IE3082-cryptogroup
    ```

2.  **Run the installation script:**
    ```bash
    chmod +x install.py
    sudo python3 install.py
    ```

3.  The installation will:
    - Install required Python packages (handles PEP 668)
    - Set up the `cryp` command for system-wide access
    - Verify the installation

## ▶️ Usage

After installation, you can use the toolkit with the `cryp` command:

### General Help
```bash
cryp -h
cryp --help

# This command will use all algorithms to encrypt the file and compare performance
cryp ini en <fileName>

# This command will benchmark the corresponding decryption processes (requires <fileName>_en directory)
cryp ini de <fileName>

# Encrypt a file with a generated key (creates <fileName>_encrypted/ folder)
cryp ini en ones <fileName>

# Decrypt the file (finds key/nonce automatically in the folder)
cryp ini de ones <path_to_encrypted_file>/<fileName>.enc

# Generate AES key
cryp aes generate-key <key_file>

# Encrypt a file
cryp aes encrypt <input_file> <key_file> <nonce_file> <output_file>

# Decrypt a file
cryp aes decrypt <input_file> <key_file> <nonce_file> <output_file>

# Run AES demo
cryp aes demo

# Generate RSA key pair
cryp rsa generate-keys <private_key_file> <public_key_file>

# Encrypt a file (for small data)
cryp rsa encrypt <plaintext_file> <public_key_file> <output_file>

# Decrypt a file
cryp rsa decrypt <ciphertext_file> <private_key_file> <output_file>

# Sign a message
cryp rsa sign <message_file> <private_key_file> <signature_file>

# Verify a signature
cryp rsa verify <message_file> <signature_file> <public_key_file>

# Run RSA demo
cryp rsa demo

# Generate ECC key pair (X25519/Ed25519)
cryp ecc generate-keys <private_key_file> <public_key_file>

# Perform X25519 key exchange
cryp ecc key-exchange <private_key_file> <peer_public_key_file> <shared_secret_file>

# Sign a message using Ed25519
cryp ecc sign <message_file> <private_key_file> <signature_file>

# Verify a signature using Ed25519
cryp ecc verify <message_file> <signature_file> <public_key_file>

# Run ECC demo
cryp ecc demo

# Hash a file
cryp hash file <input_file>

# Hash text
cryp hash text <input_text>

# Verify file hash
cryp hash verify <input_file> <expected_hash>

# Run hash demo
cryp hash demo

# Run encryption benchmark (AES, RSA, ECC)
cryp bench encryption

# Run hashing benchmark
cryp bench hashing

# Run benchmark demo
cryp bench demo

