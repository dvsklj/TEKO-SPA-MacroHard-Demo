#!/bin/bash
# MacroHard Setup Script
# Generates secure keys and initializes the application

set -e

echo "=== MacroHard Security Analysis Platform - Setup ==="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Generate secure keys
echo "Generating secure keys..."

# Generate SECRET_KEY (64 bytes hex)
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")

# Generate ENCRYPTION_KEY for Fernet (32 bytes base64)
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cat > .env <<EOF
# MacroHard Environment Configuration
# Generated on $(date)

# Security Keys (KEEP THESE SECRET!)
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY

# Database
DATABASE_URL=sqlite:///instance/macrohard.db

# Flask Environment
FLASK_ENV=production
EOF
    echo "Created .env file with secure keys"
else
    echo ".env file already exists. Skipping key generation."
fi

# Create data directory
mkdir -p data
echo "Created data directory"

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip install -q -r requirements.txt

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start the application:"
echo "  1. Review the .env file and update settings if needed"
echo "  2. Run: docker-compose up -d"
echo "     OR"
echo "  3. Run: python wsgi.py"
echo ""
echo "Default admin credentials:"
echo "  Email: admin@macrohard.local"
echo "  Password: ChangeMe123!"
echo ""
echo "IMPORTANT: Change the default admin password after first login!"
