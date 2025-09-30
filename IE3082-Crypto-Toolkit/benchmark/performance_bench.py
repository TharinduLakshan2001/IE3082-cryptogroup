"""
Performance Benchmarking Module for IE3082-Crypto-Toolkit
Provides benchmarking functions for encryption/decryption and hashing operations.
"""

import os
import time
import csv
import secrets
from ..aes.aes_gcm import generate_aes_key, encrypt_file_aes, decrypt_file_aes
from ..rsa.rsa_crypto import generate_rsa_keys, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify
from ..ecc.ecc_crypto import generate_curve25519_keys, ecc_key_exchange, generate_ed25519_keys, ed25519_sign, ed25519_verify
from ..hashing.sha256_hash import hash_file_sha256, hash_text_sha256

# Try to import matplotlib, but handle the case where it's not available
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None

def create_test_file(size_kb, filename="test_file.tmp"):
    """
    Create a test file of specified size.
    
    Args:
        size_kb (int): Size of file in kilobytes
        filename (str): Name of the file to create
        
    Returns:
        str: Path to the created file
    """
    size_bytes = size_kb * 1024
    with open(filename, "wb") as f:
        f.write(secrets.token_bytes(size_bytes))
    return filename

def benchmark_encryption(file_sizes_kb, trials=3):
    """
    Benchmark encryption/decryption operations for AES, RSA, and ECC.
    
    Args:
        file_sizes_kb (list): List of file sizes in KB to test
        trials (int): Number of trials for each test
        
    Returns:
        dict: Benchmark results
    """
    results = {
        'aes': [],
        'rsa': [],
        'ecc_key_exchange': [],
        'ecc_signing': []
    }
    
    # AES Benchmarking
    print("[+] Benchmarking AES-256-GCM...")
    key = generate_aes_key()
    nonce = secrets.token_bytes(12)
    
    for size in file_sizes_kb:
        total_encrypt_time = 0
        total_decrypt_time = 0
        
        for _ in range(trials):
            # Create test file
            test_file = create_test_file(size)
            
            # Benchmark encryption
            start_time = time.time()
            encrypt_file_aes(test_file, key, nonce, f"{test_file}.enc")
            encrypt_time = time.time() - start_time
            total_encrypt_time += encrypt_time
            
            # Benchmark decryption
            start_time = time.time()
            decrypt_file_aes(f"{test_file}.enc", key, nonce, f"{test_file}.dec")
            decrypt_time = time.time() - start_time
            total_decrypt_time += decrypt_time
            
            # Clean up
            os.remove(test_file)
            os.remove(f"{test_file}.enc")
            os.remove(f"{test_file}.dec")
        
        avg_encrypt_time = total_encrypt_time / trials
        avg_decrypt_time = total_decrypt_time / trials
        
        results['aes'].append({
            'size_kb': size,
            'encrypt_time': avg_encrypt_time,
            'decrypt_time': avg_decrypt_time
        })
        
        print(f"    File size: {size}KB | Encrypt: {avg_encrypt_time:.4f}s | Decrypt: {avg_decrypt_time:.4f}s")
    
    # RSA Benchmarking
    print("[+] Benchmarking RSA-3072...")
    private_key, public_key = generate_rsa_keys()
    
    for size in file_sizes_kb[:3]:  # Limit RSA tests to smaller files due to performance
        total_encrypt_time = 0
        total_decrypt_time = 0
        total_sign_time = 0
        total_verify_time = 0
        
        for _ in range(trials):
            # Create test data (RSA has size limitations)
            test_data = secrets.token_bytes(min(size * 1024, 190))  # RSA-3072 can encrypt max ~190 bytes
            
            # Benchmark encryption
            start_time = time.time()
            ciphertext = rsa_encrypt(test_data, public_key)
            encrypt_time = time.time() - start_time
            total_encrypt_time += encrypt_time
            
            # Benchmark decryption
            start_time = time.time()
            plaintext = rsa_decrypt(ciphertext, private_key)
            decrypt_time = time.time() - start_time
            total_decrypt_time += decrypt_time
            
            # Benchmark signing
            start_time = time.time()
            signature = rsa_sign(test_data, private_key)
            sign_time = time.time() - start_time
            total_sign_time += sign_time
            
            # Benchmark verification
            start_time = time.time()
            is_valid = rsa_verify(test_data, signature, public_key)
            verify_time = time.time() - start_time
            total_verify_time += verify_time
        
        avg_encrypt_time = total_encrypt_time / trials
        avg_decrypt_time = total_decrypt_time / trials
        avg_sign_time = total_sign_time / trials
        avg_verify_time = total_verify_time / trials
        
        results['rsa'].append({
            'size_kb': size,
            'encrypt_time': avg_encrypt_time,
            'decrypt_time': avg_decrypt_time,
            'sign_time': avg_sign_time,
            'verify_time': avg_verify_time
        })
        
        print(f"    Data size: {min(size * 1024, 190)}B | Encrypt: {avg_encrypt_time:.4f}s | Decrypt: {avg_decrypt_time:.4f}s")
        print(f"                   Sign: {avg_sign_time:.4f}s | Verify: {avg_verify_time:.4f}s")
    
    # ECC Benchmarking
    print("[+] Benchmarking ECC Curve25519...")
    
    # Key Exchange Benchmarking
    alice_private, alice_public = generate_curve25519_keys()
    bob_private, bob_public = generate_curve25519_keys()
    
    total_exchange_time = 0
    for _ in range(trials * 10):  # More trials for ECC as it's fast
        start_time = time.time()
        shared_secret = ecc_key_exchange(alice_private, bob_public)
        exchange_time = time.time() - start_time
        total_exchange_time += exchange_time
    
    avg_exchange_time = total_exchange_time / (trials * 10)
    results['ecc_key_exchange'].append({
        'operation': 'key_exchange',
        'time': avg_exchange_time
    })
    print(f"    Key Exchange: {avg_exchange_time:.6f}s")
    
    # Signing/Verification Benchmarking
    signer_private, signer_public = generate_ed25519_keys()
    test_message = b"Benchmark message for EdDSA"
    
    total_sign_time = 0
    total_verify_time = 0
    for _ in range(trials * 10):  # More trials for ECC as it's fast
        # Benchmark signing
        start_time = time.time()
        signature = ed25519_sign(test_message, signer_private)
        sign_time = time.time() - start_time
        total_sign_time += sign_time
        
        # Benchmark verification
        start_time = time.time()
        is_valid = ed25519_verify(test_message, signature, signer_public)
        verify_time = time.time() - start_time
        total_verify_time += verify_time
    
    avg_sign_time = total_sign_time / (trials * 10)
    avg_verify_time = total_verify_time / (trials * 10)
    results['ecc_signing'].append({
        'operation': 'signing',
        'sign_time': avg_sign_time,
        'verify_time': avg_verify_time
    })
    print(f"    EdDSA Signing: {avg_sign_time:.6f}s | Verification: {avg_verify_time:.6f}s")
    
    return results

def benchmark_hashing(file_sizes_kb, trials=3):
    """
    Benchmark SHA-256 hashing operations.
    
    Args:
        file_sizes_kb (list): List of file sizes in KB to test
        trials (int): Number of trials for each test
        
    Returns:
        list: Hashing benchmark results
    """
    results = []
    
    print("[+] Benchmarking SHA-256 Hashing...")
    
    for size in file_sizes_kb:
        total_file_hash_time = 0
        total_text_hash_time = 0
        
        for _ in range(trials):
            # Create test file
            test_file = create_test_file(size)
            
            # Benchmark file hashing
            start_time = time.time()
            file_hash = hash_file_sha256(test_file)
            file_hash_time = time.time() - start_time
            total_file_hash_time += file_hash_time
            
            # Create test text
            test_text = secrets.token_bytes(size * 1024).decode('latin1')  # Raw bytes as text
            
            # Benchmark text hashing
            start_time = time.time()
            text_hash = hash_text_sha256(test_text)
            text_hash_time = time.time() - start_time
            total_text_hash_time += text_hash_time
            
            # Clean up
            os.remove(test_file)
        
        avg_file_hash_time = total_file_hash_time / trials
        avg_text_hash_time = total_text_hash_time / trials
        
        results.append({
            'size_kb': size,
            'file_hash_time': avg_file_hash_time,
            'text_hash_time': avg_text_hash_time
        })
        
        print(f"    File size: {size}KB | File Hash: {avg_file_hash_time:.4f}s | Text Hash: {avg_text_hash_time:.4f}s")
    
    return results

def export_results_to_csv(encryption_results, hashing_results, filename_prefix="benchmark"):
    """
    Export benchmark results to CSV files.
    
    Args:
        encryption_results (dict): Results from benchmark_encryption
        hashing_results (list): Results from benchmark_hashing
        filename_prefix (str): Prefix for output CSV files
    """
    # Export encryption results
    with open(f"{filename_prefix}_encryption.csv", "w", newline="") as csvfile:
        fieldnames = ['algorithm', 'size_kb', 'operation', 'time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # AES results
        for result in encryption_results['aes']:
            writer.writerow({
                'algorithm': 'AES-256-GCM',
                'size_kb': result['size_kb'],
                'operation': 'encrypt',
                'time': result['encrypt_time']
            })
            writer.writerow({
                'algorithm': 'AES-256-GCM',
                'size_kb': result['size_kb'],
                'operation': 'decrypt',
                'time': result['decrypt_time']
            })
        
        # RSA results
        for result in encryption_results['rsa']:
            writer.writerow({
                'algorithm': 'RSA-3072',
                'size_kb': result['size_kb'],
                'operation': 'encrypt',
                'time': result['encrypt_time']
            })
            writer.writerow({
                'algorithm': 'RSA-3072',
                'size_kb': result['size_kb'],
                'operation': 'decrypt',
                'time': result['decrypt_time']
            })
            writer.writerow({
                'algorithm': 'RSA-3072',
                'size_kb': result['size_kb'],
                'operation': 'sign',
                'time': result['sign_time']
            })
            writer.writerow({
                'algorithm': 'RSA-3072',
                'size_kb': result['size_kb'],
                'operation': 'verify',
                'time': result['verify_time']
            })
        
        # ECC results
        for result in encryption_results['ecc_key_exchange']:
            writer.writerow({
                'algorithm': 'ECC-X25519',
                'size_kb': 0,
                'operation': 'key_exchange',
                'time': result['time']
            })
        
        for result in encryption_results['ecc_signing']:
            writer.writerow({
                'algorithm': 'ECC-Ed25519',
                'size_kb': 0,
                'operation': 'sign',
                'time': result['sign_time']
            })
            writer.writerow({
                'algorithm': 'ECC-Ed25519',
                'size_kb': 0,
                'operation': 'verify',
                'time': result['verify_time']
            })
    
    # Export hashing results
    with open(f"{filename_prefix}_hashing.csv", "w", newline="") as csvfile:
        fieldnames = ['size_kb', 'file_hash_time', 'text_hash_time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in hashing_results:
            writer.writerow(result)
    
    print(f"[+] Benchmark results exported to {filename_prefix}_encryption.csv and {filename_prefix}_hashing.csv")

def plot_benchmark_results(encryption_results, hashing_results, filename_prefix="benchmark"):
    """
    Generate plots for benchmark results.
    
    Args:
        encryption_results (dict): Results from benchmark_encryption
        hashing_results (list): Results from benchmark_hashing
        filename_prefix (str): Prefix for output plot files
    """
    # Check if matplotlib is available
    if not MATPLOTLIB_AVAILABLE:
        print("[-] Matplotlib not available. Skipping plot generation.")
        print("    To enable plotting, install matplotlib: pip install matplotlib")
        return
    
    try:
        # Plot encryption performance
        plt.figure(figsize=(12, 8))
        
        # AES encryption/decryption
        aes_sizes = [r['size_kb'] for r in encryption_results['aes']]
        aes_encrypt_times = [r['encrypt_time'] for r in encryption_results['aes']]
        aes_decrypt_times = [r['decrypt_time'] for r in encryption_results['aes']]
        
        plt.subplot(2, 2, 1)
        plt.plot(aes_sizes, aes_encrypt_times, marker='o', label='AES Encrypt')
        plt.plot(aes_sizes, aes_decrypt_times, marker='s', label='AES Decrypt')
        plt.xlabel('File Size (KB)')
        plt.ylabel('Time (seconds)')
        plt.title('AES-256-GCM Performance')
        plt.legend()
        plt.grid(True)
        
        # RSA encryption/decryption
        rsa_sizes = [r['size_kb'] for r in encryption_results['rsa']]
        rsa_encrypt_times = [r['encrypt_time'] for r in encryption_results['rsa']]
        rsa_decrypt_times = [r['decrypt_time'] for r in encryption_results['rsa']]
        
        plt.subplot(2, 2, 2)
        plt.plot(rsa_sizes, rsa_encrypt_times, marker='o', label='RSA Encrypt')
        plt.plot(rsa_sizes, rsa_decrypt_times, marker='s', label='RSA Decrypt')
        plt.xlabel('Data Size (KB)')
        plt.ylabel('Time (seconds)')
        plt.title('RSA-3072 Performance')
        plt.legend()
        plt.grid(True)
        
        # ECC performance
        ecc_key_exchange_time = encryption_results['ecc_key_exchange'][0]['time']
        ecc_sign_time = encryption_results['ecc_signing'][0]['sign_time']
        ecc_verify_time = encryption_results['ecc_signing'][0]['verify_time']
        
        plt.subplot(2, 2, 3)
        plt.bar(['Key Exchange', 'Sign', 'Verify'], 
                [ecc_key_exchange_time, ecc_sign_time, ecc_verify_time])
        plt.ylabel('Time (seconds)')
        plt.title('ECC Curve25519 Performance')
        plt.tick_params(axis='x', rotation=45)
        
        # Hashing performance
        hash_sizes = [r['size_kb'] for r in hashing_results]
        file_hash_times = [r['file_hash_time'] for r in hashing_results]
        text_hash_times = [r['text_hash_time'] for r in hashing_results]
        
        plt.subplot(2, 2, 4)
        plt.plot(hash_sizes, file_hash_times, marker='o', label='File Hash')
        plt.plot(hash_sizes, text_hash_times, marker='s', label='Text Hash')
        plt.xlabel('Size (KB)')
        plt.ylabel('Time (seconds)')
        plt.title('SHA-256 Hashing Performance')
        plt.legend()
        plt.grid(True)
        
        plt.tight_layout()
        plt.savefig(f"{filename_prefix}_performance.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"[+] Performance plots saved to {filename_prefix}_performance.png")
    except Exception as e:
        print(f"[-] Error generating plots: {e}")

def benchmark_demo():
    """Demonstrate benchmarking functionality."""
    print("[+] Performance Benchmarking Demo Starting...")
    
    # Define test parameters
    file_sizes = [1, 10, 100]  # KB
    trials = 2
    
    # Run encryption benchmarks
    encryption_results = benchmark_encryption(file_sizes, trials)
    
    # Run hashing benchmarks
    hashing_results = benchmark_hashing(file_sizes, trials)
    
    # Export results
    export_results_to_csv(encryption_results, hashing_results, "demo_benchmark")
    
    # Generate plots
    plot_benchmark_results(encryption_results, hashing_results, "demo_benchmark")
    
    print("[+] Benchmarking Demo Completed!")

if __name__ == "__main__":
    benchmark_demo()
