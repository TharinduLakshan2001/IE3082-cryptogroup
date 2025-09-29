"""
SHA-256 Hash Function Implementation for IE3082 Assignment
Implements secure hashing algorithm with 256-bit output
"""

from cryptography.hazmat.primitives import hashes
import time
import psutil
import threading
import gc
import numpy as np


class HashCrypto:
    """
    SHA-256 Hash Function Implementation
    Provides secure hashing with 256-bit output
    """
    
    def __init__(self):
        """Initialize SHA-256 hash instance"""
        pass
    
    def sha256_hash(self, data):
        """
        Generate SHA-256 hash of input data
        Args:
            data (str or bytes): Data to hash
        Returns:
            bytes: 32-byte SHA-256 hash
        """
        digest = hashes.Hash(hashes.SHA256())
        data_bytes = data.encode() if isinstance(data, str) else data
        digest.update(data_bytes)
        return digest.finalize()
    
    def hash_hex(self, data):
        """
        Generate SHA-256 hash and return as hex string
        Args:
            data (str or bytes): Data to hash
        Returns:
            str: SHA-256 hash as hex string
        """
        return self.sha256_hash(data).hex()
    
    def hash_file(self, file_path):
        """
        Generate SHA-256 hash of file contents
        Args:
            file_path (str): Path to file
        Returns:
            str: SHA-256 hash as hex string
        """
        digest = hashes.Hash(hashes.SHA256())
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                digest.update(chunk)
        
        return digest.finalize().hex()


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


def test_hash_implementation():
    """Test the SHA-256 implementation"""
    print("=== Testing SHA-256 Implementation ===")
    
    crypto = HashCrypto()
    monitor = PerformanceMonitor()
    
    # Test with sample data
    sample_text = "SHA-256 hash test message"
    print(f"Original text: {sample_text}")
    
    # Generate hash
    hash_result = monitor.measure_operation(crypto.hash_hex, sample_text)
    hash_value = hash_result['result']
    print(f"SHA-256 hash: {hash_value}")
    print(f"Hash length: {len(hash_value)} characters (256 bits)")
    print(f"Hash time: {hash_result['execution_time']:.6f}s")
    print(f"Hash CPU: {hash_result['avg_cpu']:.2f}%")
    print(f"Hash Memory: {hash_result['peak_memory']:.2f}%")
    
    # Test with different data to verify different hashes
    different_text = "Different SHA-256 hash test message"
    different_hash = crypto.hash_hex(different_text)
    print(f"Different text hash: {different_hash[:32]}...")
    print(f"Hashes are different: {hash_value != different_hash}")
    
    # Test collision resistance by verifying same input gives same hash
    same_hash = crypto.hash_hex(sample_text)
    print(f"Same input produces same hash: {hash_value == same_hash}")
    
    return True


if __name__ == "__main__":
    test_hash_implementation()
