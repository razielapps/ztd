#!/usr/bin/env bash
# install.sh - Installation script for ZeroTrustDjango Scanner

set -e

echo "Installing ZeroTrustDjango Security Scanner..."

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements-scanner.txt

# Install safety and pip-audit for dependency checking
pip install safety pip-audit

# Install OWASP ZAP Python API if available
pip install python-owasp-zap-v2.4 || echo "OWASP ZAP API not installed, skipping..."

# Make scanner executable
chmod +x zero_trust_scanner.py

echo ""
echo "Installation complete!"
echo ""
echo "To use the scanner:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run scanner: ./zero_trust_scanner.py /path/to/django/project"
echo ""
echo "For security scan: ./zero_trust_scanner.py /path/to/project --type security"
echo "For normal Django tests: ./zero_trust_scanner.py /path/to/project --type normal"
