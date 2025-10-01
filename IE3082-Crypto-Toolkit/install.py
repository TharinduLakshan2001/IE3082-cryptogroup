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

def check_python_version():
    """Check if Python 3.6+ is installed."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 6):
        print_error("Python 3.6+ is required. Please upgrade your Python installation.")
        return False
    return True

def run_command(command, description="", check=True, shell=True):
    """Run a shell command and handle errors."""
    if description:
        print_info(f"{description}...")
    
    try:
        # Use shell=True for string commands, shell=False for list commands if needed for better security
        result = subprocess.run(command, shell=shell, check=check, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              text=True)
        if result.stdout:
            # Optionally print stdout, but often it's too verbose
            # print(result.stdout)
            pass
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

def install_system_dependencies():
    """Install required system dependencies."""
    print_header("Installing system dependencies...")
    
    # Update package list
    print_info("Updating package list...")
    if not run_command("apt update", check=False):
        print_warning("Failed to update package list. Continuing with installation...")

    system_packages = [
        "python3",
        "python3-pip",
        "python3-full", # Recommended for PEP 668 compliance
        "python3-dev",  # Development headers, often needed
        "build-essential" # Build tools
    ]
    
    for package in system_packages:
        if not run_command(f"apt install -y {package}", f"Installing {package}", check=False):
             print_warning(f"Failed to install system package: {package}. Continuing...")
    
    print_success("System dependency installation attempt completed.")

def install_python_packages_from_requirements():
    """Install Python packages listed in requirements.txt."""
    print_header("Installing Python dependencies from requirements.txt...")
    
    # First try to upgrade pip
    print_info("Upgrading pip...")
    run_command("python3 -m pip install --upgrade pip", check=False)
    
    # Check for requirements.txt
    requirements_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(requirements_file):
        print_warning(f"requirements.txt not found at {requirements_file}")
        return False

    print_info(f"Found requirements.txt at {requirements_file}")
    
    # Try to install from requirements.txt using various methods
    # Method 1: Standard pip install (may hit PEP 668 issues)
    print_info("Attempting to install packages using pip (standard method)...")
    if run_command(f"python3 -m pip install -r {requirements_file}", check=False):
        print_success("Successfully installed packages from requirements.txt (standard method)")
        return True
    else:
        print_warning("Standard pip install failed (likely due to PEP 668). Trying alternatives...")
    
    # Method 2: pip install with --break-system-packages (common workaround in Kali)
    print_info("Attempting to install packages using pip with --break-system-packages...")
    if run_command(f"python3 -m pip install --break-system-packages -r {requirements_file}", check=False):
        print_success("Successfully installed packages from requirements.txt (--break-system-packages)")
        return True
    else:
        print_warning("--break-system-packages method also failed.")
        
    # Method 3: Install system packages via apt (fallback for common ones)
    print_info("Falling back to installing system packages via apt...")
    apt_fallback_map = {
        "cryptography": "python3-cryptography",
        "matplotlib": "python3-matplotlib",
        "psutil": "python3-psutil"
    }
    
    success_count = 0
    try:
        with open(requirements_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            package_line = line.strip()
            if not package_line or package_line.startswith('#'):
                continue
            
            # Extract package name (basic parsing, might need improvement for complex specs)
            package_name = package_line.split('>=')[0].split('==')[0].split('>')[0].split('<')[0].split('<=')[0].split('~=')[0]
            
            if package_name in apt_fallback_map:
                apt_package = apt_fallback_map[package_name]
                print_info(f"Installing {apt_package} via apt...")
                if run_command(f"apt install -y {apt_package}", check=False):
                    print_success(f"Installed {apt_package} via apt")
                    success_count += 1
                else:
                    print_error(f"Failed to install {apt_package} via apt")
            else:
                 print_warning(f"No apt fallback for package: {package_name}")
                 
    except Exception as e:
        print_error(f"Error during apt fallback installation: {e}")
        
    if success_count == len(apt_fallback_map):
        print_success("Successfully installed all packages via apt fallback.")
        return True
    else:
        print_warning("Apt fallback did not install all packages.")
        
    return False

def setup_toolkit():
    """Set up the toolkit for system-wide usage."""
    print_header("Setting up IE3082-Crypto-Toolkit...")
    
    # Get current directory
    toolkit_dir = os.path.dirname(os.path.abspath(__file__))
    cryp_script = os.path.join(toolkit_dir, "cryp.py")
    
    # Make cryp.py executable
    if not run_command(f"chmod +x {cryp_script}", "Making cryp.py executable"):
        print_error("Failed to make cryp.py executable")
        return False
    
    # Create symlink in /usr/local/bin (requires root)
    print_info("Creating system-wide command 'cryp'...")
    if not run_command("mkdir -p /usr/local/bin", check=False):
        print_warning("Could not create /usr/local/bin directory")
    
    # Try to create symlink
    if run_command(f"ln -sf {cryp_script} /usr/local/bin/cryp", check=False):
        print_success("Created symlink /usr/local/bin/cryp")
        return True
    else:
        # If symlink fails, try copying
        print_warning("Could not create symlink, trying to copy...")
        if run_command(f"cp {cryp_script} /usr/local/bin/cryp", check=False):
            run_command("chmod +x /usr/local/bin/cryp", check=False)
            print_success("Copied cryp to /usr/local/bin/")
            return True
        else:
            print_warning("Could not install to /usr/local/bin/")
            print_info(f"You can run the tool directly with: python3 {cryp_script}")
            return False # Don't consider this a hard failure for the whole script

def verify_installation():
    """Verify that the installation was successful."""
    print_header("Verifying installation...")
    
    # Check if cryp command is available
    if run_command("which cryp", "Checking if 'cryp' command is available", check=False):
        print_success("'cryp' command is available system-wide")
    else:
        print_warning("'cryp' command is not available system-wide")
        print_info("You can run the tool directly with: python3 cryp.py")
    
    # Test importing core modules
    core_modules = {
        'aes.aes_gcm': 'generate_aes_key',
        'rsa.rsa_crypto': 'generate_rsa_keys',
        'ecc.ecc_crypto': 'generate_curve25519_keys',
        'hashing.sha256_hash': 'hash_text_sha256'
    }
    
    all_imports_successful = True
    for module_path, function_name in core_modules.items():
        try:
            # Dynamically import the module and get the function
            module = importlib.import_module(module_path)
            getattr(module, function_name) # Check if function exists
            print_success(f"Module {module_path} imported successfully")
        except Exception as e:
            print_error(f"Failed to import {module_path}: {e}")
            all_imports_successful = False
            
    if not all_imports_successful:
        return False
    
    # Test core functionality
    try:
        from aes.aes_gcm import generate_aes_key
        key = generate_aes_key()
        if len(key) == 32:
            print_success("AES key generation working")
        else:
            print_error("AES key generation failed")
            return False
    except Exception as e:
        print_error(f"Core functionality test failed: {e}")
        return False
    
    # Verify specific required packages are available
    required_packages = ['cryptography', 'matplotlib', 'psutil']
    for pkg in required_packages:
        if is_package_installed(pkg):
            print_success(f"{pkg} is available")
        else:
            # Special check for psutil which might be installed via apt
            if pkg == 'psutil':
                try:
                    import psutil
                    print_success("psutil is available (imported successfully)")
                except ImportError:
                    print_warning("psutil is not available. Memory profiling will be limited.")
            else:
                print_warning(f"{pkg} is not available.")
    
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
    
    # Check for root privileges (recommended for system-wide installation)
    if os.geteuid() != 0:
        print_warning("Not running as root. System-wide installation (symlink creation) may fail.")
        print_info("Consider running with sudo for full installation:")
        print("  sudo python3 install.py")
        print()
    
    # Install system dependencies
    install_system_dependencies()
    
    # Install Python packages from requirements.txt
    if not install_python_packages_from_requirements():
        print_error("Failed to install Python packages from requirements.txt")
        print_info("You may need to install them manually.")
        # Decide if this is fatal - for a crypto toolkit, it probably is.
        # sys.exit(1) # Uncomment if you want this to be fatal
    
    # Set up toolkit
    if not setup_toolkit():
        print_warning("Toolkit setup (creating 'cryp' command) may be incomplete.")
        # Not necessarily fatal, user can run via python3 cryp.py
    
    # Verify installation
    if not verify_installation():
        print_error("Installation verification failed")
        # Not necessarily fatal, but warns user something might be wrong
        # sys.exit(1) # Uncomment if you want this to be fatal
    
    print_header("Installation Process Complete!")
    print_info("Please note:")
    print("  - If you saw warnings about PEP 668 or system packages, packages might be installed via apt.")
    print("  - If 'cryp' command creation failed, run the tool with: python3 cryp.py")
    print()
    print_success("IE3082-Crypto-Toolkit installation process finished!")
    print()
    print_info("You can now use the tool:")
    print("  cryp -h          # Show help (if symlink worked)")
    print("  python3 cryp.py -h # Show help (direct execution)")
    print("  cryp aes demo    # Run AES demo")
    print("  cryp rsa demo    # Run RSA demo")
    print("  cryp ecc demo    # Run ECC demo")
    print("  cryp hash demo   # Run Hash demo")
    print("  cryp bench demo  # Run Benchmark demo")
    print()
    print_info("For system-wide access, you may need to restart your terminal.")
    print()
    print_info("Documentation and examples can be found in the README.md file.")

if __name__ == "__main__":
    main()
