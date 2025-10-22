#!/usr/bin/env python3
"""
Test Suite for IE3082-Crypto-Toolkit
Comprehensive tests to verify all functionality is working properly.
"""

import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import all modules
from aes.aes_gcm import generate_aes_key, encrypt_file_aes, decrypt_file_aes, aes_demo
from rsa.rsa_crypto import generate_rsa_keys, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify, save_rsa_keys, rsa_demo
from ecc.ecc_crypto import generate_curve25519_keys, ecc_key_exchange, generate_ed25519_keys, ed25519_sign, ed25519_verify, ecc_demo
from hashing.sha256_hash import hash_file_sha256, hash_text_sha256, verify_file_hash, hash_demo
from benchmark.performance_bench import benchmark_encryption, benchmark_hashing, export_results_to_csv, benchmark_demo
from utils.color_utils import print_tool_header, print_header, print_success, print_error, print_info, print_warning

class TestResult:
    def __init__(self, name, passed, message=""):
        self.name = name
        self.passed = passed
        self.message = message

class CryptoToolkitTester:
    def __init__(self):
        self.results = []
        self.temp_dir = tempfile.mkdtemp()
        print_info(f"Created temporary directory: {self.temp_dir}")
    
    def run_test(self, test_name, test_func):
        """Run a single test and record the result."""
        try:
            result = test_func()
            self.results.append(TestResult(test_name, result, "Test passed"))
            print_success(f"✓ {test_name}")
        except Exception as e:
            self.results.append(TestResult(test_name, False, str(e)))
            print_error(f"✗ {test_name}: {str(e)}")
    
    def test_aes_functionality(self):
        """Test AES encryption/decryption functionality."""
        print_info("Testing AES functionality...")
        
        # Test key generation
        key = generate_aes_key()
        assert len(key) == 32, f"Key length is {len(key)}, expected 32"
        
        # Create test file
        test_file = os.path.join(self.temp_dir, "test_aes.txt")
        test_data = b"Test data for AES encryption"
        with open(test_file, 'wb') as f:
            f.write(test_data)
        
        # Encrypt file
        nonce = os.urandom(12)
        tag = encrypt_file_aes(test_file, key, nonce, test_file + ".enc")
        
        # Decrypt file
        decrypt_file_aes(test_file + ".enc", key, nonce, test_file + ".dec")
        
        # Verify decryption
        with open(test_file + ".dec", 'rb') as f:
            decrypted_data = f.read()
        
        assert decrypted_data == test_data, "Decrypted data doesn't match original"
        
        # Cleanup
        os.remove(test_file)
        os.remove(test_file + ".enc")
        os.remove(test_file + ".dec")
        
        return True
    
    def test_rsa_functionality(self):
        """Test RSA encryption/decryption and signing/verification."""
        print_info("Testing RSA functionality...")
        
        # Generate keys
        private_key, public_key = generate_rsa_keys()
        
        # Test data
        test_data = b"Test data for RSA encryption"
        
        # Encrypt and decrypt
        ciphertext = rsa_encrypt(test_data, public_key)
        plaintext = rsa_decrypt(ciphertext, private_key)
        assert plaintext == test_data, "RSA decryption failed"
        
        # Test signing and verification
        signature = rsa_sign(test_data, private_key)
        is_valid = rsa_verify(test_data, signature, public_key)
        assert is_valid, "RSA signature verification failed"
        
        # Test invalid signature
        is_valid_false = rsa_verify(b"wrong data", signature, public_key)
        assert not is_valid_false, "RSA verification should fail for wrong data"
        
        return True
    
    def test_ecc_functionality(self):
        """Test ECC key exchange and EdDSA signing/verification."""
        print_info("Testing ECC functionality...")
        
        # Generate X25519 key pairs
        alice_private, alice_public = generate_curve25519_keys()
        bob_private, bob_public = generate_curve25519_keys()
        
        # Test key exchange
        alice_shared = ecc_key_exchange(alice_private, bob_public)
        bob_shared = ecc_key_exchange(bob_private, alice_public)
        assert alice_shared == bob_shared, "ECC shared secrets don't match"
        
        # Generate Ed25519 keys
        signer_private, signer_public = generate_ed25519_keys()
        test_message = b"Test message for EdDSA"
        
        # Test signing and verification
        signature = ed25519_sign(test_message, signer_private)
        is_valid = ed25519_verify(test_message, signature, signer_public)
        assert is_valid, "Ed25519 verification failed"
        
        # Test invalid signature
        is_valid_false = ed25519_verify(b"wrong message", signature, signer_public)
        assert not is_valid_false, "Ed25519 verification should fail for wrong message"
        
        return True
    
    def test_hashing_functionality(self):
        """Test SHA-256 hashing functionality."""
        print_info("Testing hashing functionality...")
        
        # Test file hashing
        test_file = os.path.join(self.temp_dir, "test_hash.txt")
        test_data = b"Test data for SHA-256 hashing"
        with open(test_file, 'wb') as f:
            f.write(test_data)
        
        file_hash = hash_file_sha256(test_file)
        assert len(file_hash) == 64, f"SHA-256 hash should be 64 chars, got {len(file_hash)}"
        
        # Test text hashing
        text_hash = hash_text_sha256("Test data for SHA-256 hashing")
        assert text_hash == file_hash, "File hash and text hash should match"
        
        # Test hash verification
        is_valid = verify_file_hash(test_file, file_hash)
        assert is_valid, "Hash verification failed"
        
        # Test invalid hash verification
        is_valid_false = verify_file_hash(test_file, "a" * 64)
        assert not is_valid_false, "Hash verification should fail for wrong hash"
        
        # Cleanup
        os.remove(test_file)
        
        return True
    
    def test_benchmark_functionality(self):
        """Test benchmark functionality."""
        print_info("Testing benchmark functionality...")
        
        # Test encryption benchmark with small file sizes
        encryption_results = benchmark_encryption([1], trials=2)
        assert 'aes' in encryption_results, "AES results missing"
        assert 'rsa' in encryption_results, "RSA results missing"
        assert 'ecc_key_exchange' in encryption_results, "ECC key exchange results missing"
        assert 'ecc_signing' in encryption_results, "ECC signing results missing"
        
        # Test hashing benchmark
        hashing_results = benchmark_hashing([1], trials=2)
        assert len(hashing_results) > 0, "Hashing results empty"
        
        # Test CSV export
        export_results_to_csv(encryption_results, hashing_results, "test_export")
        
        # Check if CSV files were created
        assert os.path.exists("test_export_encryption.csv"), "Encryption CSV not created"
        assert os.path.exists("test_export_hashing.csv"), "Hashing CSV not created"
        
        # Cleanup
        os.remove("test_export_encryption.csv")
        os.remove("test_export_hashing.csv")
        
        return True
    
    def test_demo_functions(self):
        """Test demo functions (they should run without errors)."""
        print_info("Testing demo functions...")
        
        # These should run without exceptions
        aes_demo()
        rsa_demo()
        ecc_demo()
        hash_demo()
        benchmark_demo()
        
        return True
    
    def test_cli_interface(self):
        """Test CLI interface through subprocess calls."""
        print_info("Testing CLI interface...")
        
        # Test help command
        result = subprocess.run(['python3', 'cryp.py', '--help'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        assert result.returncode == 0, f"CLI help command failed: {result.stderr}"
        assert "USAGE:" in result.stdout, "Help output doesn't contain USAGE"
        
        # Test AES demo command
        result = subprocess.run(['python3', 'cryp.py', 'aes', 'demo'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        assert result.returncode == 0, f"AES demo command failed: {result.stderr}"
        
        # Test RSA demo command
        result = subprocess.run(['python3', 'cryp.py', 'rsa', 'demo'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        assert result.returncode == 0, f"RSA demo command failed: {result.stderr}"
        
        # Test ECC demo command
        result = subprocess.run(['python3', 'cryp.py', 'ecc', 'demo'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        assert result.returncode == 0, f"ECC demo command failed: {result.stderr}"
        
        # Test hash demo command
        result = subprocess.run(['python3', 'cryp.py', 'hash', 'demo'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        assert result.returncode == 0, f"Hash demo command failed: {result.stderr}"
        
        # Test benchmark demo command (if benchmark module is available)
        result = subprocess.run(['python3', 'cryp.py', 'bench', 'demo'], 
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        # This might fail if matplotlib is not installed, so we'll allow it to fail gracefully
        if result.returncode != 0:
            print_warning(f"Benchmark demo command failed (this might be due to missing matplotlib): {result.stderr}")
        
        return True
    
    def run_all_tests(self):
        """Run all tests."""
        print_tool_header()
        print_header("Running IE3082-Crypto-Toolkit Test Suite")
        print("=" * 70)
        
        # Run individual tests
        self.run_test("AES Functionality", self.test_aes_functionality)
        self.run_test("RSA Functionality", self.test_rsa_functionality)
        self.run_test("ECC Functionality", self.test_ecc_functionality)
        self.run_test("Hashing Functionality", self.test_hashing_functionality)
        self.run_test("Benchmark Functionality", self.test_benchmark_functionality)
        self.run_test("Demo Functions", self.test_demo_functions)
        self.run_test("CLI Interface", self.test_cli_interface)
        
        # Print summary
        print("\n" + "=" * 70)
        print_header("Test Results Summary")
        
        passed_tests = [r for r in self.results if r.passed]
        failed_tests = [r for r in self.results if not r.passed]
        
        print(f"Total tests: {len(self.results)}")
        print(f"Passed: {len(passed_tests)}")
        print(f"Failed: {len(failed_tests)}")
        
        if failed_tests:
            print("\nFailed tests:")
            for test in failed_tests:
                print(f"  ✗ {test.name}: {test.message}")
            return False
        else:
            print_success("\n✓ All tests passed!")
            return True
    
    def cleanup(self):
        """Clean up temporary files."""
        print_info(f"Cleaning up temporary directory: {self.temp_dir}")
        shutil.rmtree(self.temp_dir)

def main():
    tester = CryptoToolkitTester()
    try:
        success = tester.run_all_tests()
        if not success:
            sys.exit(1)
    finally:
        tester.cleanup()

if __name__ == "__main__":
    main()
