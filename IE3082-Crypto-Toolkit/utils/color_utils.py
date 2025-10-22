#!/usr/bin/env python3
"""
Color Utilities Module for IE3082-Crypto-Toolkit

Provides functions for colored console output.
"""

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    # Optional: Underline, etc.
    # UNDERLINE = '\033[4m'


def print_header(text):
    """Print a header with cyan color and bold."""
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

# Example usage if run directly (optional)
if __name__ == "__main__":
    print_tool_header()
    print_header("Testing Color Utilities")
    print_success("This is a success message.")
    print_error("This is an error message.")
    print_warning("This is a warning message.")
    print_info("This is an info message.")
