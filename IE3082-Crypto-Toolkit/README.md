# IE3082-Crypto-Toolkit

Advanced Kali Linux Encryption and Decryption Tool with AES-256-GCM, RSA-3072, ECC (Curve25519), and SHA-256.

## 🛡️ Overview

IE3082-Crypto-Toolkit is a comprehensive cryptographic tool suite designed for Kali Linux. It provides implementations of industry-standard encryption algorithms with a user-friendly command-line interface.

## 🚀 Features

### 1. Symmetric Encryption (AES-256-GCM)
- File encryption and decryption with AES-256-GCM
- Authenticated encryption with integrity verification
- Key and nonce generation

### 2. Asymmetric Encryption (RSA-3072)
- RSA key pair generation
- Message encryption and decryption
- Digital signatures and verification

### 3. Asymmetric Encryption (ECC Curve25519)
- X25519 key pair generation
- Diffie-Hellman key exchange
- Ed25519 digital signatures and verification

### 4. Hashing (SHA-256)
- File hashing
- Text hashing
- Hash verification

### 5. Performance Benchmarking
- Encryption/decryption performance testing
- Hashing performance testing
- CSV result export
- Graphical result visualization

## 📁 Project Structure

```
IE3082-Crypto-Toolkit/
├── aes/
│   └── aes_gcm.py          # AES-256-GCM implementation
├── rsa/
│   └── rsa_crypto.py       # RSA-3072 implementation
├── ecc/
│   └── ecc_crypto.py       # ECC Curve25519 implementation
├── hashing/
│   └── sha256_hash.py      # SHA-256 implementation
├── benchmark/
│   └── performance_bench.py # Benchmarking utilities
├── utils/
│   └── color_utils.py      # Colorful output utilities
├── cryp.py                 # Main CLI interface
├── install.py              # Installation script
└── README.md               # This file
```

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd IE3082-Crypto-Toolkit
   ```

2. Run the installation script:
   ```bash
   chmod +x install.py
   sudo python3 install.py
   ```

3. The installation will:
   - Install required Python packages
   - Set up the `cryp` command for system-wide access
   - Verify the installation

## ▶️ Usage

After installation, you can use the toolkit with the `cryp` command:

### General Help
```bash
cryp -h
cryp --help
```
### Automate The Whole Process

```bash
#This command will Use all algorithums to encrypt the file 
cryp ini en <fileName>
```

### AES-256-GCM Operations
```bash
# Generate AES key
cryp aes generate-key <key_file>

# Encrypt a file
cryp aes encrypt <input_file> <key_file> <nonce_file> <output_file>

# Decrypt a file
cryp aes decrypt <input_file> <key_file> <nonce_file> <output_file>

# Run AES demo
cryp aes demo
```

### RSA-3072 Operations
```bash
# Generate RSA key pair
cryp rsa generate-keys <private_key_file> <public_key_file>

# Encrypt a file
cryp rsa encrypt <plaintext_file> <public_key_file> <output_file>

# Decrypt a file
cryp rsa decrypt <ciphertext_file> <private_key_file> <output_file>

# Sign a message
cryp rsa sign <message_file> <private_key_file> <signature_file>

# Verify a signature
cryp rsa verify <message_file> <signature_file> <public_key_file>

# Run RSA demo
cryp rsa demo
```

### ECC Curve25519 Operations
```bash
# Generate ECC key pair
cryp ecc generate-keys <private_key_file> <public_key_file>

# Perform key exchange
cryp ecc key-exchange <private_key_file> <peer_public_key_file> <shared_secret_file>

# Sign a message
cryp ecc sign <message_file> <private_key_file> <signature_file>

# Verify a signature
cryp ecc verify <message_file> <signature_file> <public_key_file>

# Run ECC demo
cryp ecc demo
```

### SHA-256 Hashing Operations
```bash
# Hash a file
cryp hash file <input_file>

# Hash text
cryp hash text <input_text>

# Verify file hash
cryp hash verify <input_file> <expected_hash>

# Run hash demo
cryp hash demo
```

### Performance Benchmarking
```bash
# Run encryption benchmark
cryp bench encryption

# Run hashing benchmark
cryp bench hashing

# Run benchmark demo
cryp bench demo
```

## 🧪 Examples

### Example 1: AES File Encryption
```bash
# Generate a key
cryp aes generate-key mykey.key

# Encrypt a file (this will generate a nonce automatically)
cryp aes encrypt myfile.txt mykey.key mynonce.nonce encrypted.bin

# Decrypt the file
cryp aes decrypt encrypted.bin mykey.key mynonce.nonce decrypted.txt
```

### Example 2: RSA Message Signing
```bash
# Generate RSA key pair
cryp rsa generate-keys privkey.pem pubkey.pem

# Create a message file
echo "This is a secret message" > message.txt

# Sign the message
cryp rsa sign message.txt privkey.pem signature.sig

# Verify the signature
cryp rsa verify message.txt signature.sig pubkey.pem
```

### Example 3: ECC Key Exchange
```bash
# Generate key pairs for two parties
cryp ecc generate-keys alice_priv.pem alice_pub.pem
cryp ecc generate-keys bob_priv.pem bob_pub.pem

# Perform key exchange (Alice's perspective)
cryp ecc key-exchange alice_priv.pem bob_pub.pem alice_shared.secret

# Perform key exchange (Bob's perspective)
cryp ecc key-exchange bob_priv.pem alice_pub.pem bob_shared.secret

# Both alice_shared.secret and bob_shared.secret will contain the same shared secret
```

## 📊 Benchmarking

The toolkit includes comprehensive benchmarking capabilities:

```bash
# Run encryption benchmarks
cryp bench encryption

# Run hashing benchmarks
cryp bench hashing

# Run demo benchmarks
cryp bench demo
```

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
