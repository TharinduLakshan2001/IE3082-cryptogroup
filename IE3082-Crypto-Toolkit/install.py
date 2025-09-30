#!/usr/bin/env python3
"""
Installation Script for IE3082-Crypto-Toolkit
Automatically installs all dependencies and sets up the toolkit on Kali Linux.
"""

import os
import sys
import subprocess
import importlib.util

# Simple color codes for output (without external dependencies)
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

def check_python_version():
    """Check if Python 3.6+ is installed."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 6):
        print_error("Python 3.6+ is required. Please upgrade your Python installation.")
        return False
    return True

def run_command(command, description="", check=True):
    """Run a shell command and handle errors."""
    if description:
        print_info(f"{description}...")
    
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              text=True)
        if result.stdout:
            print(result.stdout)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        if check:
            print_error(f"Command failed: {command}")
            print_error(f"Error: {e.stderr}")
        return False
    except Exception as e:
        if check:
            print_error(f"Error running command: {command}")
            print_error(f"Error: {str(e)}")
        return False

def is_package_installed(package_name):
    """Check if a Python package is installed."""
    try:
        importlib.util.find_spec(package_name)
        return True
    except ImportError:
        return False

def install_python_packages():
    """Install required Python packages."""
    print_header("Installing Python dependencies...")
    
    packages = [
        ("cryptography", "cryptography"),
        ("matplotlib", "matplotlib")
    ]
    
    # First try to upgrade pip
    print_info("Upgrading pip...")
    run_command("python3 -m pip install --upgrade pip", check=False)
    
    all_installed = True
    for package_import, package_name in packages:
        if is_package_installed(package_import):
            print_success(f"{package_name} is already installed")
            continue
            
        print_info(f"Installing {package_name}...")
        # Try multiple installation methods
        install_methods = [
            f"python3 -m pip install {package_name}",
            f"pip3 install {package_name}",
            f"pip install {package_name}",
            f"apt install -y python3-{package_name}" if package_name != "matplotlib" else "apt install -y python3-matplotlib",
        ]
        
        installed = False
        for method in install_methods:
            if run_command(method, check=False):
                installed = True
                break
        
        if not installed:
            print_warning(f"Failed to install {package_name} with automatic methods")
            print_info("Please install it manually with one of these commands:")
            for method in install_methods:
                print(f"  {method}")
            all_installed = False
        else:
            print_success(f"Successfully installed {package_name}")
    
    if all_installed:
        print_success("All Python packages installed successfully!")
    return all_installed

def setup_toolkit():
    """Set up the toolkit for system-wide usage."""
    print_header("Setting up IE3082-Crypto-Toolkit...")
    
    # Get current directory
    toolkit_dir = os.path.dirname(os.path.abspath(__file__))
    cryp_script = os.path.join(toolkit_dir, "cryp.py")
    
    # Make cryp.py executable
    if not run_command(f"chmod +x {cryp_script}", "Making cryp.py executable"):
        return False
    
    # Create symlink in /usr/local/bin
    print_info("Creating system-wide command 'cryp'...")
    if not run_command("mkdir -p /usr/local/bin", check=False):
        print_warning("Could not create /usr/local/bin directory")
    
    # Try to create symlink
    if run_command(f"ln -sf {cryp_script} /usr/local/bin/cryp", check=False):
        print_success("Created symlink /usr/local/bin/cryp")
    else:
        # If symlink fails, try copying
        print_warning("Could not create symlink, trying to copy...")
        if run_command(f"cp {cryp_script} /usr/local/bin/cryp", check=False):
            run_command("chmod +x /usr/local/bin/cryp", check=False)
            print_success("Copied cryp to /usr/local/bin/")
        else:
            print_warning("Could not install to /usr/local/bin/")
            print_info(f"You can run the tool directly with: python3 {cryp_script}")
    
    return True

def verify_installation():
    """Verify that the installation was successful."""
    print_header("Verifying installation...")
    
    # Check if cryp command is available
    if run_command("which cryp", "Checking if 'cryp' command is available", check=False):
        print_success("'cryp' command is available system-wide")
    else:
        print_warning("'cryp' command is not available system-wide")
        print_info("You can run the tool directly with: python3 cryp.py")
    
    # Test importing modules
    try:
        # Test importing core modules
        from aes.aes_gcm import generate_aes_key
        from rsa.rsa_crypto import generate_rsa_keys
        from ecc.ecc_crypto import generate_curve25519_keys
        from hashing.sha256_hash import hash_text_sha256
        print_success("All modules imported successfully")
    except Exception as e:
        print_error(f"Module import failed: {e}")
        return False
    
    # Test core functionality
    try:
        key = generate_aes_key()
        if len(key) == 32:
            print_success("AES key generation working")
        else:
            print_error("AES key generation failed")
            return False
    except Exception as e:
        print_error(f"Core functionality test failed: {e}")
        return False
    
    return True

def main():
    """Main installation function."""
    print_tool_header()
    print_header("IE3082-Crypto-Toolkit Installation")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check if running on Kali Linux
    print_info("Checking system...")
    if os.path.exists("/etc/kali-release"):
        print_success("Kali Linux detected")
    else:
        print_warning("This tool is designed for Kali Linux. You may encounter issues on other systems.")
    
    # Update package list
    print_info("Updating package list...")
    run_command("apt update", check=False)
    
    # Install system dependencies
    print_header("Installing system dependencies...")
    system_packages = [
        "python3",
        "python3-pip"
    ]
    
    for package in system_packages:
        run_command(f"apt install -y {package}", f"Installing {package}", check=False)
    
    # Install Python packages
    if not install_python_packages():
        print_warning("Some Python packages failed to install. You may need to install them manually.")
    
    # Set up toolkit
    if not setup_toolkit():
        print_error("Failed to set up toolkit")
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        print_error("Installation verification failed")
        sys.exit(1)
    
    print_header("Installation Complete!")
    print_success("IE3082-Crypto-Toolkit has been successfully installed!")
    print()
    print_info("You can now use the tool with the 'cryp' command:")
    print("  cryp -h          # Show help")
    print("  cryp aes demo    # Run AES demo")
    print("  cryp rsa demo    # Run RSA demo")
    print("  cryp ecc demo    # Run ECC demo")
    print("  cryp hash demo   # Run Hash demo")
    print()
    print_info("For system-wide access, you may need to restart your terminal or run:")
    print("  source ~/.bashrc")
    print()
    print_info("Documentation and examples can be found in the README.md file.")

if __name__ == "__main__":
    # Check if running as root (recommended for system-wide installation)
    if os.geteuid() != 0:
        print_warning("Running installation without root privileges. System-wide installation may fail.")
        print_info("For full installation, run with sudo:")
        print("  sudo python3 install.py")
        print()
    
    main()