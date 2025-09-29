"""
AES-256-GCM Implementation for IE3082 Assignment
Implements authenticated encryption with 256-bit key
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import psutil
import threading
import gc
import numpy as np


class AESGCMCrypto:
    """
    AES-256-GCM Cryptographic Implementation
    Provides authenticated encryption and decryption
    """
    
    def __init__(self):
        """Initialize AES-GCM instance"""
        self.aesgcm = None
    
    def generate_key(self):
        """
        Generate a secure 256-bit (32 bytes) key using CSPRNG
        Returns:
            bytes: 32-byte key for AES-256
        """
        return os.urandom(32)
    
    def encrypt(self, plaintext, key):
        """
        Encrypt plaintext using AES-256-GCM
        Args:
            plaintext (str or bytes): Data to encrypt
            key (bytes): 32-byte AES-256 key
        Returns:
            bytes: Encrypted data (nonce + ciphertext + auth_tag)
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        plaintext_bytes = plaintext.encode() if isinstance(plaintext, str) else plaintext
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
        # Store nonce with ciphertext for decryption
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data, key):
        """
        Decrypt data using AES-256-GCM
        Args:
            encrypted_data (bytes): Encrypted data (nonce + ciphertext + auth_tag)
            key (bytes): 32-byte AES-256 key
        Returns:
            str: Decrypted plaintext
        """
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode() if isinstance(plaintext, bytes) else plaintext
    
    def encrypt_file(self, input_file_path, output_file_path, key):
        """
        Encrypt a file using AES-256-GCM
        Args:
            input_file_path (str): Path to input file
            output_file_path (str): Path to output file
            key (bytes): 32-byte AES-256 key
        """
        with open(input_file_path, 'rb') as f:
            plaintext = f.read()
        
        encrypted_data = self.encrypt(plaintext, key)
        
        with open(output_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"File encrypted: {input_file_path} -> {output_file_path}")
        print(f"Original size: {len(plaintext)} bytes")
        print(f"Encrypted size: {len(encrypted_data)} bytes")
    
    def decrypt_file(self, input_file_path, output_file_path, key):
        """
        Decrypt a file using AES-256-GCM
        Args:
            input_file_path (str): Path to encrypted file
            output_file_path (str): Path to output file
            key (bytes): 32-byte AES-256 key
        """
        with open(input_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.decrypt(encrypted_data, key)
        
        with open(output_file_path, 'w') as f:
            f.write(decrypted_data)
        
        print(f"File decrypted: {input_file_path} -> {output_file_path}")
        print(f"Decrypted content length: {len(decrypted_data)} characters")


class PerformanceMonitor:
    """
    Performance monitoring for cryptographic operations
    Measures time, CPU usage, and memory usage
    """
    
    def __init__(self):
        self.cpu_samples = []
        self.memory_samples = []
        self.active = False
    
    def resource_monitor(self):
        """Continuous monitoring of system resources"""
        while self.active:
            self.cpu_samples.append(psutil.cpu_percent(interval=0.05))
            self.memory_samples.append(psutil.virtual_memory().percent)
            time.sleep(0.05)
    
    def measure_operation(self, operation_func, *args):
        """
        Measure performance of a cryptographic operation
        Args:
            operation_func: Function to measure
            *args: Arguments for the function
        Returns:
            dict: Performance metrics
        """
        gc.collect()  # Clear garbage before measurement
        
        # Clear previous samples
        self.cpu_samples = []
        self.memory_samples = []
        
        # Start monitoring
        self.active = True
        monitor_thread = threading.Thread(target=self.resource_monitor)
        monitor_thread.start()
        
        start_time = time.time()
        result = operation_func(*args)
        end_time = time.time()
        
        # Stop monitoring
        self.active = False
        monitor_thread.join()
        
        return {
            'execution_time': end_time - start_time,
            'avg_cpu': np.mean(self.cpu_samples) if self.cpu_samples else 0,
            'peak_memory': max(self.memory_samples) if self.memory_samples else 0,
            'result': result
        }


def test_aes_implementation():
    """Test the AES-256-GCM implementation"""
    print("=== Testing AES-256-GCM Implementation ===")
    
    crypto = AESGCMCrypto()
    monitor = PerformanceMonitor()
    
    # Test with sample data
    sample_text = "This is a sample text for AES-256-GCM encryption demonstration. The quick brown fox jumps over the lazy dog."
    print(f"Original text: {sample_text[:50]}...")
    
    # Generate key
    key = crypto.generate_key()
    print(f"Generated key (first 16 chars): {key.hex()[:16]}...")
    
    # Encrypt
    encrypt_result = monitor.measure_operation(crypto.encrypt, sample_text, key)
    print(f"Encryption time: {encrypt_result['execution_time']:.6f}s")
    print(f"Encryption CPU: {encrypt_result['avg_cpu']:.2f}%")
    print(f"Encryption Memory: {encrypt_result['peak_memory']:.2f}%")
    
    # Decrypt
    encrypted_data = encrypt_result['result']
    decrypt_result = monitor.measure_operation(crypto.decrypt, encrypted_data, key)
    print(f"Decryption time: {decrypt_result['execution_time']:.6f}s")
    print(f"Decryption CPU: {decrypt_result['avg_cpu']:.2f}%")
    print(f"Decryption Memory: {decrypt_result['peak_memory']:.2f}%")
    
    # Verify correctness
    decrypted_text = decrypt_result['result']
    success = sample_text == decrypted_text
    print(f"Encryption/Decryption successful: {success}")
    
    return success


if __name__ == "__main__":
    test_aes_implementation()
