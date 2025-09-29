"""
ECC (Elliptic Curve Cryptography) Implementation for IE3082 Assignment
Implements digital signatures using secp256r1 curve
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import time
import psutil
import threading
import gc
import numpy as np


class ECCCrypto:
    """
    ECC (Elliptic Curve Cryptography) Implementation
    Provides digital signatures using secp256r1 curve
    """
    
    def __init__(self):
        """Initialize ECC instance with secp256r1 curve"""
        self.private_key = None
        self.public_key = None
        self.curve = ec.SECP256R1()
    
    def generate_keys(self):
        """
        Generate ECC key pair using secp256r1 curve
        Returns:
            tuple: (private_key, public_key)
        """
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def sign(self, message, private_key=None):
        """
        Create ECDSA digital signature
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
            ec.ECDSA(hashes.SHA256())
        )
    
    def verify(self, signature, message, public_key=None):
        """
        Verify ECDSA digital signature
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
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
    
    def get_curve_info(self):
        """
        Get information about the used curve
        Returns:
            dict: Curve information
        """
        return {
            'name': 'secp256r1',
            'security_level': '128-bit equivalent to AES-128',
            'key_size': 256,  # bits
            'description': 'NIST P-256 curve, also known as prime256v1'
        }


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


def test_ecc_implementation():
    """Test the ECC implementation"""
    print("=== Testing ECC Implementation (secp256r1) ===")
    
    crypto = ECCCrypto()
    monitor = PerformanceMonitor()
    
    # Generate keys
    private_key, public_key = crypto.generate_keys()
    curve_info = crypto.get_curve_info()
    print(f"Generated ECC key pair using {curve_info['name']} curve")
    print(f"Security level: {curve_info['security_level']}")
    
    # Test with sample data
    sample_text = "ECC digital signature test"
    print(f"Original text: {sample_text}")
    
    # Create signature
    signature_result = monitor.measure_operation(crypto.sign, sample_text)
    print(f"Signature time: {signature_result['execution_time']:.6f}s")
    print(f"Signature CPU: {signature_result['avg_cpu']:.2f}%")
    print(f"Signature Memory: {signature_result['peak_memory']:.2f}%")
    
    # Verify signature
    signature = signature_result['result']
    verify_result = monitor.measure_operation(crypto.verify, signature, sample_text)
    print(f"Verification time: {verify_result['execution_time']:.6f}s")
    print(f"Verification successful: {verify_result['result']}")
    
    # Test verification with wrong message
    wrong_verify_result = monitor.measure_operation(crypto.verify, signature, "wrong message")
    print(f"Verification with wrong message: {wrong_verify_result['result']}")
    
    return verify_result['result']


if __name__ == "__main__":
    test_ecc_implementation()
