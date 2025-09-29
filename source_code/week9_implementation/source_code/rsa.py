"""
RSA-3072 Implementation for IE3082 Assignment
Implements asymmetric encryption with 3072-bit keys using OAEP padding
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time
import psutil
import threading
import gc
import numpy as np


class RSACrypto:
    """
    RSA-3072 Cryptographic Implementation
    Provides asymmetric encryption and decryption with OAEP padding
    """
    
    def __init__(self, key_size=3072):
        """
        Initialize RSA instance
        Args:
            key_size (int): RSA key size in bits (default: 3072)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """
        Generate RSA-3072 key pair with secure parameters
        Returns:
            tuple: (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard secure exponent
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def encrypt(self, message, public_key=None):
        """
        RSA-OAEP encryption
        Args:
            message (str): Message to encrypt
            public_key: Public key (uses instance key if None)
        Returns:
            bytes: Encrypted data
        """
        key = public_key or self.public_key
        if key is None:
            raise ValueError("Public key not available")
        
        return key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, encrypted_data, private_key=None):
        """
        RSA-OAEP decryption
        Args:
            encrypted_data (bytes): Data to decrypt
            private_key: Private key (uses instance key if None)
        Returns:
            str: Decrypted message
        """
        key = private_key or self.private_key
        if key is None:
            raise ValueError("Private key not available")
        
        decrypted_bytes = key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes.decode()
    
    def sign(self, message, private_key=None):
        """
        Create RSA digital signature
        Args:
            message (str): Message to sign
            private_key: Private key (uses instance key if None)
        Returns:
            bytes: Digital signature
        """
        key = private_key or self.private_key
        if key is None:
            raise ValueError("Private key not available")
        
        return key.sign(
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    def verify(self, signature, message, public_key=None):
        """
        Verify RSA digital signature
        Args:
            signature (bytes): Digital signature
            message (str): Original message
            public_key: Public key (uses instance key if None)
        Returns:
            bool: True if signature is valid
        """
        key = public_key or self.public_key
        if key is None:
            raise ValueError("Public key not available")
        
        try:
            key.verify(
                signature,
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except:
            return False


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


def test_rsa_implementation():
    """Test the RSA-3072 implementation"""
    print("=== Testing RSA-3072 Implementation ===")
    
    crypto = RSACrypto(key_size=3072)
    monitor = PerformanceMonitor()
    
    # Generate keys
    private_key, public_key = crypto.generate_keys()
    print(f"Generated RSA-{crypto.key_size} key pair")
    
    # Test with sample data (limited size for RSA)
    sample_text = "RSA encryption test"  # RSA has size limitations
    print(f"Original text: {sample_text}")
    
    # Encrypt
    encrypt_result = monitor.measure_operation(crypto.encrypt, sample_text)
    print(f"Encryption time: {encrypt_result['execution_time']:.6f}s")
    print(f"Encryption CPU: {encrypt_result['avg_cpu']:.2f}%")
    print(f"Encryption Memory: {encrypt_result['peak_memory']:.2f}%")
    
    # Decrypt
    encrypted_data = encrypt_result['result']
    decrypt_result = monitor.measure_operation(crypto.decrypt, encrypted_data)
    print(f"Decryption time: {decrypt_result['execution_time']:.6f}s")
    print(f"Decryption CPU: {decrypt_result['avg_cpu']:.2f}%")
    print(f"Decryption Memory: {decrypt_result['peak_memory']:.2f}%")
    
    # Verify correctness
    decrypted_text = decrypt_result['result']
    success = sample_text == decrypted_text
    print(f"Encryption/Decryption successful: {success}")
    
    # Test digital signature
    print("\n=== Testing RSA Digital Signature ===")
    signature_result = monitor.measure_operation(crypto.sign, sample_text)
    print(f"Signature time: {signature_result['execution_time']:.6f}s")
    
    verify_result = monitor.measure_operation(crypto.verify, signature_result['result'], sample_text)
    print(f"Verification successful: {verify_result['result']}")
    
    return success


if __name__ == "__main__":
    test_rsa_implementation()
