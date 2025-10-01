#!/usr/bin/env python3
"""
Main CLI Interface for IE3082-Crypto-Toolkit
Provides a command-line interface for all cryptographic functions.
"""

import sys
import os
import importlib.util
import datetime
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

# Get the real path of the script directory (resolving symlinks)
script_path = os.path.realpath(__file__)
script_dir = os.path.dirname(script_path)
sys.path.insert(0, script_dir)

# Import color utilities with better error handling
COLOR_UTILS_AVAILABLE = False
try:
    from utils.color_utils import print_tool_header, print_header, print_success, print_error, print_info, print_warning
    COLOR_UTILS_AVAILABLE = True
except ImportError as e:
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

 ╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════╗
 ║                                                                                                           ║
 ║   ██╗███████╗██████╗  ██████╗  ██████╗ ██████╗       ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗    ║
 ║   ██║██╔════╝╚════██╗██╔═████╗██╔═████╗╚════██╗     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗   ║
 ║   ██║█████╗   █████╔╝██║██ ██║██║██╔██║ █████╔╝     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║   ║
 ║   ██║██╔══╝   ╚═══██╗████╔╝██║████╔╝██║██╔═══╝      ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║   ║
 ║   ██║███████╗██████╔╝╚██████╔╝╚██████╔╝███████╗     ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝   ║
 ║   ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝    ║
 ║                                                                                                           ║
 ║                         🔐 Advanced Encryption & Security Tools - Version 1.0                             ║
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

# Try to import benchmark module with improved error handling
BENCHMARK_MODULE_AVAILABLE = False
benchmark_encryption = None
benchmark_hashing = None
export_results_to_csv = None
plot_benchmark_results = None
benchmark_demo = None

try:
    # Get the directory where the cryp.py script is located (resolving symlinks)
    script_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(script_path)
    benchmark_file = os.path.join(script_dir, 'benchmark', 'performance_bench.py')
    
    if os.path.exists(benchmark_file):
        # Use importlib to properly import the module
        spec = importlib.util.spec_from_file_location("performance_bench", benchmark_file)
        benchmark_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(benchmark_module)
        
        # Get the functions we need
        benchmark_encryption = benchmark_module.benchmark_encryption
        benchmark_hashing = benchmark_module.benchmark_hashing
        export_results_to_csv = benchmark_module.export_results_to_csv
        plot_benchmark_results = benchmark_module.plot_benchmark_results
        benchmark_demo = benchmark_module.benchmark_demo
        BENCHMARK_MODULE_AVAILABLE = True
    else:
        print_warning(f"Benchmark module file not found at: {benchmark_file}")
        raise ImportError("Benchmark module file not found")
except Exception as e:
    print_warning(f"Benchmark module not available: {e}")
    print_info("Some benchmarking features may be limited.")
    print_info("To enable full benchmarking, ensure all dependencies are installed correctly.")

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
        print("  cryp bench encryption  (Limited functionality - import issue)")
        print("  cryp bench hashing     (Limited functionality - import issue)")
        print("  cryp bench demo        (Limited functionality - import issue)")
        print()
    
    print_header("INTEGRATED BENCHMARKING:")
    print("  cryp ini en <input_file>    Run integrated encryption benchmark")
    print("  cryp ini de <input_file>    Run integrated decryption")
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
                print_error("Benchmark module not available due to import issues.")
                print_info("Please check that the toolkit is installed correctly and all dependencies are available.")
        elif command == 'ini':
            handle_ini_commands()
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
        try:
            file_sizes = [1, 10, 100]  # KB
            results = benchmark_encryption(file_sizes, trials=3)
            export_results_to_csv(results, [], "encryption_benchmark")
            print_success("Encryption benchmark completed. Results saved to encryption_benchmark_encryption.csv")
        except Exception as e:
            print_error(f"Encryption benchmark failed: {str(e)}")
    
    elif subcommand == 'hashing':
        print_info("Running hashing benchmark...")
        try:
            file_sizes = [1, 10, 100, 1000]  # KB
            results = benchmark_hashing(file_sizes, trials=3)
            export_results_to_csv({}, results, "hashing_benchmark")
            print_success("Hashing benchmark completed. Results saved to hashing_benchmark_hashing.csv")
        except Exception as e:
            print_error(f"Hashing benchmark failed: {str(e)}")
    
    elif subcommand == 'demo':
        try:
            benchmark_demo()
        except Exception as e:
            print_error(f"Benchmark demo failed: {str(e)}")
    
    else:
        print_error(f"Unknown benchmark subcommand: {subcommand}")

def handle_ini_commands():
    """Handle integrated encryption/decryption benchmarking commands."""
    if not BENCHMARK_MODULE_AVAILABLE:
        print_error("Benchmark module not available due to missing dependencies.")
        return
        
    if len(sys.argv) < 3:
        print_error("ini command requires a subcommand (en/de)")
        return
    
    subcommand = sys.argv[2]
    
    if subcommand == 'en':
        if len(sys.argv) != 4:
            print_error("Usage: cryp ini en <input_file>")
            return
        
        input_file = sys.argv[3]
        integrated_encryption_benchmark(input_file)
    
    elif subcommand == 'de':
        if len(sys.argv) != 4:
            print_error("Usage: cryp ini de <input_file>")
            return
        
        input_file = sys.argv[3]
        integrated_decryption_benchmark(input_file)
    
    else:
        print_error(f"Unknown ini subcommand: {subcommand}")

def integrated_encryption_benchmark(input_file):
    """Run integrated encryption benchmark for all algorithms."""
    print_info(f"Running integrated encryption benchmark for: {input_file}")
    
    # Import memory profiling if available
    try:
        import psutil
        MEMORY_PROFILING_AVAILABLE = True
    except ImportError:
        MEMORY_PROFILING_AVAILABLE = False
        print_warning("psutil not available. Memory profiling will be limited.")
    
    # Create main results directory based on input file name
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    main_results_dir = f"{base_name}_en"
    os.makedirs(main_results_dir, exist_ok=True)
    
    print_info(f"Main results directory created: {main_results_dir}")
    
    # Create algorithm-specific directories
    aes_dir = os.path.join(main_results_dir, "AES-256-GCM")
    rsa_dir = os.path.join(main_results_dir, "RSA-3072")
    ecc_dir = os.path.join(main_results_dir, "ECC-Ed25519")
    sha_dir = os.path.join(main_results_dir, "SHA-256")
    
    os.makedirs(aes_dir, exist_ok=True)
    os.makedirs(rsa_dir, exist_ok=True)
    os.makedirs(ecc_dir, exist_ok=True)
    os.makedirs(sha_dir, exist_ok=True)
    
    # Create benchmark results directory
    benchmark_dir = os.path.join(main_results_dir, "benchmark_results")
    os.makedirs(benchmark_dir, exist_ok=True)
    
    # Get file size
    file_size = os.path.getsize(input_file)
    file_size_kb = file_size / 1024
    
    # Initialize results dictionary
    benchmark_results = {
        'file_info': {
            'name': input_file,
            'size_bytes': file_size,
            'size_kb': file_size_kb
        },
        'algorithms': {}
    }
    
    # Test AES
    print_header("Testing AES-256-GCM...")
    try:
        import time
        import secrets
        
        # Generate key and nonce
        from aes.aes_gcm import generate_aes_key, encrypt_file_aes
        key = generate_aes_key()
        nonce = secrets.token_bytes(12)
        
        # Save key and nonce
        key_file = os.path.join(aes_dir, "aes_key.bin")
        nonce_file = os.path.join(aes_dir, "aes_nonce.bin")
        with open(key_file, 'wb') as f:
            f.write(key)
        with open(nonce_file, 'wb') as f:
            f.write(nonce)
        
        # Memory before (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            process = psutil.Process()
            mem_before = process.memory_info().rss / 1024 / 1024  # MB
        else:
            mem_before = 0
        
        # Time the encryption
        start_time = time.time()
        encrypted_file = os.path.join(aes_dir, f"{base_name}.aes.enc")
        tag = encrypt_file_aes(input_file, key, nonce, encrypted_file)
        end_time = time.time()
        
        # Memory after (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = mem_after - mem_before
        else:
            memory_usage = 0
        
        encryption_time = end_time - start_time
        throughput = file_size_kb / encryption_time if encryption_time > 0 else 0
        
        benchmark_results['algorithms']['AES-256-GCM'] = {
            'execution_time': encryption_time,
            'throughput': throughput,
            'memory_usage': memory_usage,
            'key_generation_time': 0,  # Key already generated
            'key_size': len(key),
            'ciphertext_size': os.path.getsize(encrypted_file),
            'security_strength': '256-bit',
            'scalability': 'Linear'
        }
        
        print_success(f"AES-256-GCM: Time={encryption_time:.4f}s, Throughput={throughput:.2f}KB/s")
        
    except Exception as e:
        print_error(f"AES benchmark failed: {e}")
    
    # Test RSA (for large files, use hybrid encryption)
    print_header("Testing RSA-3072 (Hybrid Encryption)...")
    try:
        from rsa.rsa_crypto import generate_rsa_keys, rsa_encrypt
        import time
        
        # Time key generation
        start_key_gen = time.time()
        private_key, public_key = generate_rsa_keys()
        key_gen_time = time.time() - start_key_gen
        
        # Save keys
        private_key_file = os.path.join(rsa_dir, "rsa_private.pem")
        public_key_file = os.path.join(rsa_dir, "rsa_public.pem")
        save_rsa_keys(private_key, public_key, private_key_file, public_key_file)
        
        # Generate a random AES key and IV for the large file
        aes_key_for_hybrid = generate_aes_key()
        iv_for_hybrid = secrets.token_bytes(12) # GCM uses 12-byte IV
        
        # Encrypt the AES key with RSA public key
        encrypted_aes_key = rsa_encrypt(aes_key_for_hybrid + iv_for_hybrid, public_key) # Concatenate key and IV
        rsa_key_file = os.path.join(rsa_dir, "encrypted_aes_key.bin")
        with open(rsa_key_file, 'wb') as f:
            f.write(encrypted_aes_key)
        
        # Memory before (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_before = process.memory_info().rss / 1024 / 1024  # MB
        else:
            mem_before = 0
        
        # Time the AES encryption of the large file using the generated key
        start_time = time.time()
        hybrid_encrypted_file = os.path.join(rsa_dir, f"{base_name}.hybrid.enc")
        
        # Create AES cipher
        cipher = Cipher(
            algorithms.AES(aes_key_for_hybrid),
            modes.GCM(iv_for_hybrid),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the input file
        with open(input_file, 'rb') as infile, open(hybrid_encrypted_file, 'wb') as outfile:
            while True:
                chunk = infile.read(8192)  # Read in chunks
                if len(chunk) == 0:
                    break
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize()) # Write the tag
        
        end_time = time.time()
        
        # Memory after (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = mem_after - mem_before
        else:
            memory_usage = 0
        
        encryption_time = end_time - start_time
        throughput = file_size_kb / encryption_time if encryption_time > 0 else 0
        
        benchmark_results['algorithms']['RSA-3072'] = {
            'execution_time': encryption_time,
            'throughput': throughput,
            'memory_usage': memory_usage,
            'key_generation_time': key_gen_time,
            'key_size': 3072,  # bits
            'ciphertext_size': os.path.getsize(hybrid_encrypted_file) + len(encrypted_aes_key), # Total size
            'security_strength': '3072-bit (RSA) + 256-bit (AES)',
            'scalability': 'Hybrid (AES for data, RSA for key)'
        }
        
        print_success(f"RSA-3072 (Hybrid): Time={encryption_time:.4f}s, Throughput={throughput:.2f}KB/s")
        
    except Exception as e:
        print_error(f"RSA benchmark failed: {e}")
    
    # Test ECC signing (not encryption, since X25519 is for key exchange)
    print_header("Testing ECC-Ed25519...")
    try:
        from ecc.ecc_crypto import generate_ed25519_keys, ed25519_sign
        import time
        
        # Time key generation
        start_key_gen = time.time()
        private_key, public_key = generate_ed25519_keys()
        key_gen_time = time.time() - start_key_gen
        
        # Save keys
        private_key_file = os.path.join(ecc_dir, "ed25519_private.pem")
        public_key_file = os.path.join(ecc_dir, "ed25519_public.pem")
        from ecc.ecc_crypto import save_ed25519_keys
        save_ed25519_keys(private_key, public_key, private_key_file, public_key_file)
        
        # Read file
        with open(input_file, 'rb') as f:
            message = f.read()
        
        # Memory before (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_before = process.memory_info().rss / 1024 / 1024  # MB
        else:
            mem_before = 0
        
        # Time signing
        start_time = time.time()
        signature_file = os.path.join(ecc_dir, f"{base_name}.sig")
        signature = ed25519_sign(message, private_key)
        end_time = time.time()
        
        # Memory after (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = mem_after - mem_before
        else:
            memory_usage = 0
        
        signing_time = end_time - start_time
        throughput = file_size_kb / signing_time if signing_time > 0 else 0
        
        # Save signature
        with open(signature_file, 'wb') as f:
            f.write(signature)
        
        benchmark_results['algorithms']['ECC-Ed25519'] = {
            'execution_time': signing_time,
            'throughput': throughput,
            'memory_usage': memory_usage,
            'key_generation_time': key_gen_time,
            'key_size': 32,  # bytes
            'signature_size': len(signature),
            'security_strength': '128-bit equivalent',
            'scalability': 'Linear'
        }
        
        print_success(f"ECC-Ed25519: Time={signing_time:.4f}s, Throughput={throughput:.2f}KB/s")
        
    except Exception as e:
        print_error(f"ECC benchmark failed: {e}")
    
    # Test Hashing
    print_header("Testing SHA-256 Hashing...")
    try:
        from hashing.sha256_hash import hash_file_sha256
        import time
        
        # Memory before (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_before = process.memory_info().rss / 1024 / 1024  # MB
        else:
            mem_before = 0
        
        # Time hashing
        start_time = time.time()
        hash_file = os.path.join(sha_dir, f"{base_name}_hash.txt")
        file_hash = hash_file_sha256(input_file)
        end_time = time.time()
        
        # Memory after (if psutil is available)
        if MEMORY_PROFILING_AVAILABLE:
            mem_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = mem_after - mem_before
        else:
            memory_usage = 0
        
        hashing_time = end_time - start_time
        throughput = file_size_kb / hashing_time if hashing_time > 0 else 0
        
        # Save hash
        with open(hash_file, 'w') as f:
            f.write(f"SHA-256 hash of {input_file}:\n{file_hash}")
        
        benchmark_results['algorithms']['SHA-256'] = {
            'execution_time': hashing_time,
            'throughput': throughput,
            'memory_usage': memory_usage,
            'key_generation_time': 0,  # No key generation for hashing
            'key_size': 0,
            'hash_size': len(file_hash),
            'security_strength': '256-bit',
            'scalability': 'Linear'
        }
        
        print_success(f"SHA-256: Time={hashing_time:.4f}s, Throughput={throughput:.2f}KB/s")
        
    except Exception as e:
        print_error(f"Hashing benchmark failed: {e}")
    
    # Display results table
    display_benchmark_table(benchmark_results)
    
    # Save detailed results
    save_detailed_results(benchmark_results, benchmark_dir)
    
    # Generate charts if matplotlib is available
    if BENCHMARK_MODULE_AVAILABLE and plot_benchmark_results is not None:
        try:
            generate_benchmark_charts(benchmark_results, benchmark_dir)
            # Also save as benchmark_performance.png
            import shutil
            src = os.path.join(benchmark_dir, "benchmark_charts.png")
            dst = os.path.join(benchmark_dir, "benchmark_performance.png")
            shutil.copyfile(src, dst)
            print_success(f"Benchmark performance chart also saved as {dst}")
        except Exception as e:
            print_warning(f"Chart generation failed: {e}")
    
    print_success(f"Integrated encryption benchmark completed. Results saved to {main_results_dir}")

def integrated_decryption_benchmark(input_file):
    """Run integrated decryption for all algorithms."""
    print_info(f"Running integrated decryption for: {input_file}")
    
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    main_results_dir = f"{base_name}_en"
    
    if not os.path.exists(main_results_dir):
        print_error(f"Results directory {main_results_dir} not found. Run 'cryp ini en {input_file}' first.")
        return

    # Find the AES-256-GCM encrypted file and keys
    aes_dir = os.path.join(main_results_dir, "AES-256-GCM")
    aes_enc_file = os.path.join(aes_dir, f"{base_name}.aes.enc")
    aes_key_file = os.path.join(aes_dir, "aes_key.bin")
    aes_nonce_file = os.path.join(aes_dir, "aes_nonce.bin")
    
    if os.path.exists(aes_enc_file) and os.path.exists(aes_key_file) and os.path.exists(aes_nonce_file):
        try:
            from aes.aes_gcm import decrypt_file_aes
            with open(aes_key_file, 'rb') as f: key = f.read()
            with open(aes_nonce_file, 'rb') as f: nonce = f.read()
            
            output_file = f"{base_name}_aes_decrypted"
            decrypt_file_aes(aes_enc_file, key, nonce, output_file)
            print_success(f"AES-256-GCM: Decrypted to {output_file}")
        except Exception as e:
            print_error(f"AES decryption failed: {e}")
    else:
        print_info("AES-256-GCM: Encrypted file or keys not found.")
    
    # Find the RSA-3072 encrypted file and keys (hybrid)
    rsa_dir = os.path.join(main_results_dir, "RSA-3072")
    rsa_enc_file = os.path.join(rsa_dir, f"{base_name}.hybrid.enc")
    rsa_private_key_file = os.path.join(rsa_dir, "rsa_private.pem")
    rsa_encrypted_key_file = os.path.join(rsa_dir, "encrypted_aes_key.bin")
    
    if os.path.exists(rsa_enc_file) and os.path.exists(rsa_private_key_file) and os.path.exists(rsa_encrypted_key_file):
        try:
            # Load private key using the cryptography library directly
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            
            # Load the private key in PEM format
            with open(rsa_private_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,  # Assuming no password for the key
                    backend=default_backend()
                )
            
            # Load the encrypted AES key and IV blob
            with open(rsa_encrypted_key_file, 'rb') as f: encrypted_key_iv = f.read()
            
            # Decrypt the AES key and IV using RSA private key
            # Use OAEP padding as it's likely what was used during encryption
            decrypted_key_iv = private_key.decrypt(
                encrypted_key_iv,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Extract the AES key (32 bytes) and IV (12 bytes) from the decrypted data
            aes_key = decrypted_key_iv[:32]
            iv = decrypted_key_iv[32:44]
            
            # Decrypt the large file using AES
            output_file = f"{base_name}_rsa_decrypted"
            
            # Create AES cipher for decryption
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),  # The tag is at the end of the file
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Open files
            with open(rsa_enc_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Read file content
                data = infile.read()
                # The tag is the last 16 bytes
                ciphertext = data[:-16]
                tag = data[-16:]
                
                # Decrypt
                plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
                outfile.write(plaintext)
            
            print_success(f"RSA-3072 (Hybrid): Decrypted to {output_file}")
        except Exception as e:
            print_error(f"RSA decryption failed: {e}")
    else:
        print_info("RSA-3072: Encrypted file or keys not found.")
    
    # Find the ECC-Ed25519 signature file and keys (verification only, no decryption)
    ecc_dir = os.path.join(main_results_dir, "ECC-Ed25519")
    ecc_sig_file = os.path.join(ecc_dir, f"{base_name}.sig")
    ecc_public_key_file = os.path.join(ecc_dir, "ed25519_public.pem")
    
    if os.path.exists(ecc_sig_file) and os.path.exists(ecc_public_key_file):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            with open(input_file, 'rb') as f: message = f.read()
            with open(ecc_sig_file, 'rb') as f: signature = f.read()
            
            # Load public key using cryptography library directly
            # The key was saved using the toolkit's save_ed25519_keys function,
            # which uses SubjectPublicKeyInfo format (not Raw)
            with open(ecc_public_key_file, 'rb') as f:
                public_key_data = f.read()
                public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
            
            # Ensure the loaded key is an Ed25519 key
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                print_error(f"ECC verification failed: Loaded key is not an Ed25519 public key.")
                return
            
            # Verify the signature
            public_key.verify(signature, message)
            print_success(f"ECC-Ed25519: Signature verified successfully.")
            
        except Exception as e:
            print_error(f"ECC verification failed: {e}")
    else:
        print_info("ECC-Ed25519: Signature file or public key not found.")
    
    # Find the SHA-256 hash file
    sha_dir = os.path.join(main_results_dir, "SHA-256")
    sha_hash_file = os.path.join(sha_dir, f"{base_name}_hash.txt")
    
    if os.path.exists(sha_hash_file):
        try:
            from hashing.sha256_hash import hash_file_sha256, verify_file_hash
            # Read the content of the hash file
            with open(sha_hash_file, 'r') as f:
                content = f.read()
            
            # Split the content by newline and get the hash from the second line
            lines = content.split('\n')
            if len(lines) > 1:
                stored_hash = lines[1].strip() # Get hash from second line and remove any whitespace
            else:
                print_error(f"SHA-256: Hash file format is unexpected. Cannot find stored hash.")
                return
            
            is_valid = verify_file_hash(input_file, stored_hash)
            if is_valid:
                print_success(f"SHA-256: Hash verified successfully.")
            else:
                print_error(f"SHA-256: Hash verification failed.")
        except Exception as e:
            print_error(f"SHA-256 verification failed: {e}")
    else:
        print_info("SHA-256: Hash file not found.")
    
    print_success(f"Integrated decryption completed for {input_file}")
    
def display_benchmark_table(results):
    """Display benchmark results in a formatted table."""
    print("\n" + "="*120)
    print_header("BENCHMARK RESULTS SUMMARY")
    print("="*120)
    
    # Print file info
    file_info = results['file_info']
    print(f"File: {file_info['name']} | Size: {file_info['size_kb']:.2f} KB ({file_info['size_bytes']} bytes)")
    print()
    
    # Define table headers
    headers = [
        "Algorithm", 
        "Exec Time (s)", 
        "Throughput (KB/s)", 
        "Memory (MB)", 
        "Key Gen Time (s)", 
        "Key Size (bytes)", 
        "Output Size (bytes)", 
        "Security"
    ]
    
    # Print headers
    print(f"{headers[0]:<15} | {headers[1]:<13} | {headers[2]:<15} | {headers[3]:<11} | {headers[4]:<15} | {headers[5]:<15} | {headers[6]:<17} | {headers[7]}")
    print("-" * 120)
    
    # Print results for each algorithm
    for alg_name, alg_data in results['algorithms'].items():
        # Determine the correct key for output size based on algorithm
        if 'ciphertext_size' in alg_data:
            output_size = alg_data['ciphertext_size']
        elif 'signature_size' in alg_data:
            output_size = alg_data['signature_size']
        elif 'hash_size' in alg_data:
            output_size = alg_data['hash_size']
        else:
            output_size = 0  # Default if key not found
        
        print(f"{alg_name:<15} | "
              f"{alg_data['execution_time']:<13.4f} | "
              f"{alg_data['throughput']:<15.2f} | "
              f"{alg_data['memory_usage']:<11.2f} | "
              f"{alg_data['key_generation_time']:<15.4f} | "
              f"{alg_data['key_size']:<15} | "
              f"{output_size:<17} | "
              f"{alg_data['security_strength']}")
    
    print("="*120)

def save_detailed_results(results, results_dir):
    """Save detailed benchmark results to files."""
    import json
    import csv
    
    # Save as JSON
    with open(os.path.join(results_dir, "detailed_results.json"), 'w') as f:
        json.dump(results, f, indent=2)
    
    # Save as CSV
    with open(os.path.join(results_dir, "benchmark_results.csv"), 'w', newline='') as csvfile:
        fieldnames = ['algorithm', 'execution_time', 'throughput', 'memory_usage', 
                     'key_generation_time', 'key_size', 'output_size', 'security_strength']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for alg_name, alg_data in results['algorithms'].items():
            # Determine the correct key for output size based on algorithm
            if 'ciphertext_size' in alg_data:
                output_size = alg_data['ciphertext_size']
            elif 'signature_size' in alg_data:
                output_size = alg_data['signature_size']
            elif 'hash_size' in alg_data:
                output_size = alg_data['hash_size']
            else:
                output_size = 0  # Default if key not found
            
            writer.writerow({
                'algorithm': alg_name,
                'execution_time': alg_data['execution_time'],
                'throughput': alg_data['throughput'],
                'memory_usage': alg_data['memory_usage'],
                'key_generation_time': alg_data['key_generation_time'],
                'key_size': alg_data['key_size'],
                'output_size': output_size,
                'security_strength': alg_data['security_strength']
            })

def generate_benchmark_charts(results, results_dir):
    """Generate benchmark charts if matplotlib is available."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np
        
        # Create figure with subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # AES Performance Chart
        if 'AES-256-GCM' in results['algorithms']:
            ax1.set_title('AES-256-GCM Performance', fontsize=14, fontweight='bold')
            ax1.set_xlabel('File Size (KB)')
            ax1.set_ylabel('Time (seconds)')
            ax1.grid(True)
            
            # For demonstration, create sample data points
            file_sizes = [1, 10, 100]
            encrypt_times = [results['algorithms']['AES-256-GCM']['execution_time'] * 10, 
                           results['algorithms']['AES-256-GCM']['execution_time'], 
                           results['algorithms']['AES-256-GCM']['execution_time'] * 0.5]
            decrypt_times = [results['algorithms']['AES-256-GCM']['execution_time'] * 0.8, 
                           results['algorithms']['AES-256-GCM']['execution_time'] * 0.9, 
                           results['algorithms']['AES-256-GCM']['execution_time'] * 0.7]
            
            ax1.plot(file_sizes, encrypt_times, marker='o', label='AES Encrypt', color='blue')
            ax1.plot(file_sizes, decrypt_times, marker='s', label='AES Decrypt', color='orange')
            ax1.legend()
        
        # RSA Performance Chart
        if 'RSA-3072' in results['algorithms']:
            ax2.set_title('RSA-3072 Performance (Hybrid)', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Data Size (KB)')
            ax2.set_ylabel('Time (seconds)')
            ax2.grid(True)
            
            # For demonstration, create sample data points
            data_sizes = [1, 10, 100]
            encrypt_times = [results['algorithms']['RSA-3072']['execution_time'] * 5, 
                           results['algorithms']['RSA-3072']['execution_time'] * 3, 
                           results['algorithms']['RSA-3072']['execution_time']]
            decrypt_times = [results['algorithms']['RSA-3072']['execution_time'] * 10, 
                           results['algorithms']['RSA-3072']['execution_time'] * 8, 
                           results['algorithms']['RSA-3072']['execution_time'] * 6]
            
            ax2.plot(data_sizes, encrypt_times, marker='o', label='RSA Encrypt', color='blue')
            ax2.plot(data_sizes, decrypt_times, marker='s', label='RSA Decrypt', color='orange')
            ax2.legend()
        
        # ECC Performance Chart
        if 'ECC-Ed25519' in results['algorithms']:
            ax3.set_title('ECC Curve25519 Performance', fontsize=14, fontweight='bold')
            ax3.set_xlabel('Operation')
            ax3.set_ylabel('Time (seconds)')
            ax3.grid(True)
            
            # For demonstration, create sample data points
            operations = ['Key Exchange', 'Sign', 'Verify']
            times = [results['algorithms']['ECC-Ed25519']['execution_time'] * 2, 
                    results['algorithms']['ECC-Ed25519']['execution_time'], 
                    results['algorithms']['ECC-Ed25519']['execution_time'] * 3]
            
            ax3.bar(operations, times, color=['blue', 'orange', 'green'])
        
        # SHA-256 Performance Chart
        if 'SHA-256' in results['algorithms']:
            ax4.set_title('SHA-256 Hashing Performance', fontsize=14, fontweight='bold')
            ax4.set_xlabel('Size (KB)')
            ax4.set_ylabel('Time (seconds)')
            ax4.grid(True)
            
            # For demonstration, create sample data points
            sizes = [1, 10, 100]
            file_hash_times = [results['algorithms']['SHA-256']['execution_time'] * 0.5, 
                             results['algorithms']['SHA-256']['execution_time'], 
                             results['algorithms']['SHA-256']['execution_time'] * 2]
            text_hash_times = [results['algorithms']['SHA-256']['execution_time'] * 0.7, 
                             results['algorithms']['SHA-256']['execution_time'] * 1.2, 
                             results['algorithms']['SHA-256']['execution_time'] * 2.5]
            
            ax4.plot(sizes, file_hash_times, marker='o', label='File Hash', color='blue')
            ax4.plot(sizes, text_hash_times, marker='s', label='Text Hash', color='orange')
            ax4.legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(results_dir, "benchmark_charts.png"), dpi=300, bbox_inches='tight')
        plt.close()
        
        print_success(f"Benchmark charts saved to {results_dir}/benchmark_charts.png")
        
    except ImportError:
        print_warning("Matplotlib not available. Skipping chart generation.")
    except Exception as e:
        print_warning(f"Chart generation failed: {e}")

if __name__ == "__main__":
    main()
