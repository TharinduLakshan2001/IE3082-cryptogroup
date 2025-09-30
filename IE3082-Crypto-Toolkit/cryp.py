#!/usr/bin/env python3
"""
Main CLI Interface for IE3082-Crypto-Toolkit
Provides a command-line interface for all cryptographic functions.
"""

import sys
import os
import argparse

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import color utilities
try:
    from utils.color_utils import print_tool_header, print_header, print_success, print_error, print_info, print_warning
except ImportError:
    # Fallback color utilities if the module can't be imported
    class Colors:
        RESET = '\033[0m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        BOLD = '\033[1m'

    def print_header(text):
        """Print a header with cyan color."""
        print(f"{Colors.CYAN}{Colors.BOLD}{text}{Colors.RESET}")

    def print_success(text):
        """Print a success message with green color."""
        print(f"{Colors.GREEN}[+] {text}{Colors.RESET}")

    def print_error(text):
        """Print an error message with red color."""
        print(f"{Colors.RED}[-] {text}{Colors.RESET}")

    def print_warning(text):
        """Print a warning message with yellow color."""
        print(f"{Colors.YELLOW}[!] {text}{Colors.RESET}")

    def print_info(text):
        """Print an info message with blue color."""
        print(f"{Colors.BLUE}[i] {text}{Colors.RESET}")

    def print_tool_header():
        """Print the IE3082-Crypto-Toolkit header."""
        header = r"""

╔════════════════════════════════════════════════════════════════════════════════════════════════════════ ══╗
║                                                                                                           ║
║   ██╗███████╗██████╗  ██████╗  ██████╗ ██████╗       ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗    ║
║   ██║██╔════╝╚════██╗██╔═████╗██╔═████╗╚════██╗     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗   ║
║   ██║█████╗   █████╔╝██║██ ██║██║██╔██║ █████╔╝     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║   ║
║   ██║██╔══╝   ╚═══██╗████╔╝██║████╔╝██║██╔═══╝      ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║   ║
║   ██║███████╗██████╔╝╚██████╔╝╚██████╔╝███████╗     ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝   ║
║   ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝    ║
║                                                                                                           ║
║                         🔐 Advanced Encryption & Security Tools - {self.version}                          ║
║                                                                                                           ║
║                                IT22249852 -- P.M.T.L. KARUNARATHNA                                        ║
║                                                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝
                                                            
        """
        print(f"{Colors.CYAN}{Colors.BOLD}{header}{Colors.RESET}")
        print(f"{Colors.YELLOW}{Colors.BOLD}IE3082-Crypto-Toolkit - Advanced Cryptographic Tool Suite{Colors.RESET}")
        print(f"{Colors.MAGENTA}Version 1.0 | Kali Linux Encryption and Decryption Tool{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

# Import all modules with error handling
try:
    from aes.aes_gcm import generate_aes_key, encrypt_file_aes, decrypt_file_aes, aes_demo
except ImportError as e:
    print_error(f"Failed to import AES module: {e}")
    sys.exit(1)

try:
    from rsa.rsa_crypto import generate_rsa_keys, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify, save_rsa_keys, load_rsa_keys, rsa_demo
except ImportError as e:
    print_error(f"Failed to import RSA module: {e}")
    sys.exit(1)

try:
    from ecc.ecc_crypto import generate_curve25519_keys, ecc_key_exchange, generate_ed25519_keys, ed25519_sign, ed25519_verify, ecc_demo
except ImportError as e:
    print_error(f"Failed to import ECC module: {e}")
    sys.exit(1)

try:
    from hashing.sha256_hash import hash_file_sha256, hash_text_sha256, verify_file_hash, hash_demo
except ImportError as e:
    print_error(f"Failed to import Hashing module: {e}")
    sys.exit(1)

# Try to import benchmark module, but handle the case where matplotlib is missing
BENCHMARK_MODULE_AVAILABLE = True
try:
    from benchmark.performance_bench import benchmark_encryption, benchmark_hashing, export_results_to_csv, plot_benchmark_results, benchmark_demo
except ImportError as e:
    print_warning(f"Benchmark module not available: {e}")
    print_info("Some benchmarking features may be limited.")
    print_info("To enable full benchmarking, install matplotlib: pip install matplotlib")
    BENCHMARK_MODULE_AVAILABLE = False

def show_help():
    """Display help information."""
    print_tool_header()
    print_header("USAGE:")
    print("  cryp <command> [options]")
    print()
    
    print_header("SYMMETRIC ENCRYPTION (AES-256-GCM):")
    print("  cryp aes encrypt <input_file> <key_file> <nonce_file> <output_file>")
    print("  cryp aes decrypt <input_file> <key_file> <nonce_file> <output_file>")
    print("  cryp aes generate-key <key_file>")
    print("  cryp aes demo")
    print()
    
    print_header("ASYMMETRIC ENCRYPTION (RSA-3072):")
    print("  cryp rsa generate-keys <private_key_file> <public_key_file>")
    print("  cryp rsa encrypt <plaintext_file> <public_key_file> <output_file>")
    print("  cryp rsa decrypt <ciphertext_file> <private_key_file> <output_file>")
    print("  cryp rsa sign <message_file> <private_key_file> <signature_file>")
    print("  cryp rsa verify <message_file> <signature_file> <public_key_file>")
    print("  cryp rsa demo")
    print()
    
    print_header("ASYMMETRIC ENCRYPTION (ECC Curve25519):")
    print("  cryp ecc generate-keys <private_key_file> <public_key_file>")
    print("  cryp ecc key-exchange <private_key_file> <peer_public_key_file> <shared_secret_file>")
    print("  cryp ecc sign <message_file> <private_key_file> <signature_file>")
    print("  cryp ecc verify <message_file> <signature_file> <public_key_file>")
    print("  cryp ecc demo")
    print()
    
    print_header("HASHING (SHA-256):")
    print("  cryp hash file <input_file>")
    print("  cryp hash text <input_text>")
    print("  cryp hash verify <input_file> <expected_hash>")
    print("  cryp hash demo")
    print()
    
    # Only show benchmarking options if the module is available
    if BENCHMARK_MODULE_AVAILABLE:
        print_header("BENCHMARKING:")
        print("  cryp bench encryption")
        print("  cryp bench hashing")
        print("  cryp bench demo")
        print()
    else:
        print_header("BENCHMARKING (Limited):")
        print("  cryp bench encryption  (Limited functionality - matplotlib not installed)")
        print("  cryp bench hashing     (Limited functionality - matplotlib not installed)")
        print("  cryp bench demo        (Limited functionality - matplotlib not installed)")
        print()
    
    print_header("GENERAL:")
    print("  cryp -h, cryp --help     Show this help message")
    print()

def main():
    """Main entry point for the CLI."""
    if len(sys.argv) < 2:
        show_help()
        return
    
    # Handle help commands
    if sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        return
    
    command = sys.argv[1]
    
    try:
        if command == 'aes':
            handle_aes_commands()
        elif command == 'rsa':
            handle_rsa_commands()
        elif command == 'ecc':
            handle_ecc_commands()
        elif command == 'hash':
            handle_hash_commands()
        elif command == 'bench':
            if BENCHMARK_MODULE_AVAILABLE:
                handle_bench_commands()
            else:
                print_error("Benchmark module not available due to missing dependencies (matplotlib).")
                print_info("To enable benchmarking, install matplotlib: pip install matplotlib")
        else:
            print_error(f"Unknown command: {command}")
            show_help()
    except Exception as e:
        print_error(f"An error occurred: {str(e)}")
        if '--debug' in sys.argv:
            raise

def handle_aes_commands():
    """Handle AES-related commands."""
    if len(sys.argv) < 3:
        print_error("AES command requires a subcommand")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'generate-key':
        if len(sys.argv) != 4:
            print_error("Usage: cryp aes generate-key <key_file>")
            return
        
        key_file = sys.argv[3]
        key = generate_aes_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        print_success(f"AES key generated and saved to {key_file}")
    
    elif subcommand == 'encrypt':
        if len(sys.argv) != 7:
            print_error("Usage: cryp aes encrypt <input_file> <key_file> <nonce_file> <output_file>")
            return
        
        input_file, key_file, nonce_file, output_file = sys.argv[3:7]
        
        # Read key
        with open(key_file, 'rb') as f:
            key = f.read()
        
        # Generate or read nonce
        if os.path.exists(nonce_file):
            with open(nonce_file, 'rb') as f:
                nonce = f.read()
        else:
            import secrets
            nonce = secrets.token_bytes(12)
            with open(nonce_file, 'wb') as f:
                f.write(nonce)
            print_info(f"Generated new nonce and saved to {nonce_file}")
        
        # Encrypt file
        tag = encrypt_file_aes(input_file, key, nonce, output_file)
        print_success(f"File encrypted successfully. Output saved to {output_file}")
    
    elif subcommand == 'decrypt':
        if len(sys.argv) != 7:
            print_error("Usage: cryp aes decrypt <input_file> <key_file> <nonce_file> <output_file>")
            return
        
        input_file, key_file, nonce_file, output_file = sys.argv[3:7]
        
        # Read key
        with open(key_file, 'rb') as f:
            key = f.read()
        
        # Read nonce
        with open(nonce_file, 'rb') as f:
            nonce = f.read()
        
        # Decrypt file
        try:
            decrypt_file_aes(input_file, key, nonce, output_file)
            print_success(f"File decrypted successfully. Output saved to {output_file}")
        except Exception as e:
            print_error(f"Decryption failed: {str(e)}")
    
    elif subcommand == 'demo':
        aes_demo()
    
    else:
        print_error(f"Unknown AES subcommand: {subcommand}")

def handle_rsa_commands():
    """Handle RSA-related commands."""
    if len(sys.argv) < 3:
        print_error("RSA command requires a subcommand")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'generate-keys':
        if len(sys.argv) != 5:
            print_error("Usage: cryp rsa generate-keys <private_key_file> <public_key_file>")
            return
        
        private_key_file, public_key_file = sys.argv[3:5]
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key, private_key_file, public_key_file)
        print_success(f"RSA key pair generated and saved to {private_key_file} and {public_key_file}")
    
    elif subcommand == 'encrypt':
        if len(sys.argv) != 6:
            print_error("Usage: cryp rsa encrypt <plaintext_file> <public_key_file> <output_file>")
            return
        
        plaintext_file, public_key_file, output_file = sys.argv[3:6]
        
        # Read plaintext
        with open(plaintext_file, 'rb') as f:
            plaintext = f.read()
        
        # Load public key
        with open(public_key_file, 'rb') as f:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        # Encrypt
        ciphertext = rsa_encrypt(plaintext, public_key)
        
        # Save ciphertext
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        
        print_success(f"File encrypted successfully. Output saved to {output_file}")
    
    elif subcommand == 'decrypt':
        if len(sys.argv) != 6:
            print_error("Usage: cryp rsa decrypt <ciphertext_file> <private_key_file> <output_file>")
            return
        
        ciphertext_file, private_key_file, output_file = sys.argv[3:6]
        
        # Read ciphertext
        with open(ciphertext_file, 'rb') as f:
            ciphertext = f.read()
        
        # Load private key
        with open(private_key_file, 'rb') as f:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        # Decrypt
        try:
            plaintext = rsa_decrypt(ciphertext, private_key)
            
            # Save plaintext
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print_success(f"File decrypted successfully. Output saved to {output_file}")
        except Exception as e:
            print_error(f"Decryption failed: {str(e)}")
    
    elif subcommand == 'sign':
        if len(sys.argv) != 6:
            print_error("Usage: cryp rsa sign <message_file> <private_key_file> <signature_file>")
            return
        
        message_file, private_key_file, signature_file = sys.argv[3:6]
        
        # Read message
        with open(message_file, 'rb') as f:
            message = f.read()
        
        # Load private key
        with open(private_key_file, 'rb') as f:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        # Sign
        signature = rsa_sign(message, private_key)
        
        # Save signature
        with open(signature_file, 'wb') as f:
            f.write(signature)
        
        print_success(f"Message signed successfully. Signature saved to {signature_file}")
    
    elif subcommand == 'verify':
        if len(sys.argv) != 6:
            print_error("Usage: cryp rsa verify <message_file> <signature_file> <public_key_file>")
            return
        
        message_file, signature_file, public_key_file = sys.argv[3:6]
        
        # Read message
        with open(message_file, 'rb') as f:
            message = f.read()
        
        # Read signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
        
        # Load public key
        with open(public_key_file, 'rb') as f:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        # Verify
        is_valid = rsa_verify(message, signature, public_key)
        
        if is_valid:
            print_success("Signature is valid!")
        else:
            print_error("Signature is invalid!")
    
    elif subcommand == 'demo':
        rsa_demo()
    
    else:
        print_error(f"Unknown RSA subcommand: {subcommand}")

def handle_ecc_commands():
    """Handle ECC-related commands."""
    if len(sys.argv) < 3:
        print_error("ECC command requires a subcommand")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'generate-keys':
        if len(sys.argv) != 5:
            print_error("Usage: cryp ecc generate-keys <private_key_file> <public_key_file>")
            return
        
        private_key_file, public_key_file = sys.argv[3:5]
        
        # Generate X25519 keys
        private_key, public_key = generate_curve25519_keys()
        
        # Save keys
        from cryptography.hazmat.primitives import serialization
        with open(private_key_file, 'wb') as f:
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(private_bytes)
        
        with open(public_key_file, 'wb') as f:
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.Raw
            )
            f.write(public_bytes)
        
        print_success(f"ECC key pair generated and saved to {private_key_file} and {public_key_file}")
    
    elif subcommand == 'key-exchange':
        if len(sys.argv) != 6:
            print_error("Usage: cryp ecc key-exchange <private_key_file> <peer_public_key_file> <shared_secret_file>")
            return
        
        private_key_file, peer_public_key_file, shared_secret_file = sys.argv[3:6]
        
        # Load private key
        from cryptography.hazmat.primitives.asymmetric import x25519
        with open(private_key_file, 'rb') as f:
            private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())
        
        # Load peer's public key
        with open(peer_public_key_file, 'rb') as f:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(f.read())
        
        # Perform key exchange
        shared_secret = ecc_key_exchange(private_key, peer_public_key)
        
        # Save shared secret
        with open(shared_secret_file, 'wb') as f:
            f.write(shared_secret)
        
        print_success(f"Key exchange completed. Shared secret saved to {shared_secret_file}")
    
    elif subcommand == 'sign':
        if len(sys.argv) != 6:
            print_error("Usage: cryp ecc sign <message_file> <private_key_file> <signature_file>")
            return
        
        message_file, private_key_file, signature_file = sys.argv[3:6]
        
        # Read message
        with open(message_file, 'rb') as f:
            message = f.read()
        
        # Load private key
        from cryptography.hazmat.primitives.asymmetric import ed25519
        with open(private_key_file, 'rb') as f:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        
        # Sign
        signature = ed25519_sign(message, private_key)
        
        # Save signature
        with open(signature_file, 'wb') as f:
            f.write(signature)
        
        print_success(f"Message signed successfully. Signature saved to {signature_file}")
    
    elif subcommand == 'verify':
        if len(sys.argv) != 6:
            print_error("Usage: cryp ecc verify <message_file> <signature_file> <public_key_file>")
            return
        
        message_file, signature_file, public_key_file = sys.argv[3:6]
        
        # Read message
        with open(message_file, 'rb') as f:
            message = f.read()
        
        # Read signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
        
        # Load public key
        from cryptography.hazmat.primitives.asymmetric import ed25519
        with open(public_key_file, 'rb') as f:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(f.read())
        
        # Verify
        is_valid = ed25519_verify(message, signature, public_key)
        
        if is_valid:
            print_success("Signature is valid!")
        else:
            print_error("Signature is invalid!")
    
    elif subcommand == 'demo':
        ecc_demo()
    
    else:
        print_error(f"Unknown ECC subcommand: {subcommand}")

def handle_hash_commands():
    """Handle hashing-related commands."""
    if len(sys.argv) < 3:
        print_error("Hash command requires a subcommand")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'file':
        if len(sys.argv) != 4:
            print_error("Usage: cryp hash file <input_file>")
            return
        
        input_file = sys.argv[3]
        file_hash = hash_file_sha256(input_file)
        print_success(f"SHA-256 hash of {input_file}:")
        print(file_hash)
    
    elif subcommand == 'text':
        if len(sys.argv) != 4:
            print_error("Usage: cryp hash text <input_text>")
            return
        
        input_text = sys.argv[3]
        text_hash = hash_text_sha256(input_text)
        print_success(f"SHA-256 hash of text:")
        print(text_hash)
    
    elif subcommand == 'verify':
        if len(sys.argv) != 5:
            print_error("Usage: cryp hash verify <input_file> <expected_hash>")
            return
        
        input_file, expected_hash = sys.argv[3:5]
        is_valid = verify_file_hash(input_file, expected_hash)
        
        if is_valid:
            print_success("File hash verification: PASSED")
        else:
            print_error("File hash verification: FAILED")
    
    elif subcommand == 'demo':
        hash_demo()
    
    else:
        print_error(f"Unknown hash subcommand: {subcommand}")

def handle_bench_commands():
    """Handle benchmarking-related commands."""
    if not BENCHMARK_MODULE_AVAILABLE:
        print_error("Benchmark module not available due to missing dependencies.")
        return
        
    if len(sys.argv) < 3:
        print_error("Benchmark command requires a subcommand")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'encryption':
        print_info("Running encryption benchmark...")
        file_sizes = [1, 10, 100]  # KB
        results = benchmark_encryption(file_sizes, trials=3)
        export_results_to_csv(results, [], "encryption_benchmark")
        print_success("Encryption benchmark completed. Results saved to encryption_benchmark_encryption.csv")
    
    elif subcommand == 'hashing':
        print_info("Running hashing benchmark...")
        file_sizes = [1, 10, 100, 1000]  # KB
        results = benchmark_hashing(file_sizes, trials=3)
        export_results_to_csv({}, results, "hashing_benchmark")
        print_success("Hashing benchmark completed. Results saved to hashing_benchmark_hashing.csv")
    
    elif subcommand == 'demo':
        benchmark_demo()
    
    else:
        print_error(f"Unknown benchmark subcommand: {subcommand}")

if __name__ == "__main__":
    print_tool_header()
    main()
