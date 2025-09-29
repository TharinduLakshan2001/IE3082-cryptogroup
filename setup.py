#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="crypto-toolkit",
    version="1.0.0",
    description="IE3082 Cryptography Assignment Toolkit",
    author="IE3082 Group",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4.8",
        "matplotlib>=3.3.0",
        "pandas>=1.1.0",
        "numpy>=1.19.0",
        "psutil>=5.8.0"
    ],
    entry_points={
        'console_scripts': [
            'cryp=crypto.cli:main',
        ],
    },
    python_requires='>=3.6',
)
