"""
Color Utilities for IE3082-Crypto-Toolkit
Provides colorful output for better user experience.
"""

# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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

def print_bold(text):
    """Print bold text."""
    print(f"{Colors.BOLD}{text}{Colors.RESET}")

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

if __name__ == "__main__":
    # Demo the color utilities
    print_tool_header()
    print_header("Header Text")
    print_success("Success message")
    print_error("Error message")
    print_warning("Warning message")
    print_info("Info message")
    print_bold("Bold text")
