#!/bin/bash
# MacroHard Quick Start Script
# Gets you up and running in seconds

set -e

echo "==================================="
echo "  MacroHard Quick Start"
echo "  Security Analysis Platform"
echo "==================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed."
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is required but not installed."
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Ask user for mode
echo "Select mode:"
echo "  1) Demo Mode - Pre-populated with sample data (recommended for first try)"
echo "  2) Production Mode - Clean slate with secure defaults"
echo ""
read -p "Enter choice [1-2]: " choice

case $choice in
    1)
        echo ""
        echo "Starting MacroHard in DEMO mode..."
        echo "This will create a demo user with sample projects and vulnerabilities."
        echo ""
        
        # Generate keys if not present
        if [ ! -f .env ]; then
            echo "Generating secure keys..."
            SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))" 2>/dev/null || echo "demo-secret-key-change-in-production")
            ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo "demo-encryption-key-change-in-production")
            
            cat > .env <<EOF
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
DATABASE_URL=sqlite:///instance/macrohard.db
FLASK_ENV=production
DEMO_MODE=true
EOF
        fi
        
        # Start with demo mode
        export DEMO_MODE=true
        docker-compose up -d --build
        
        echo ""
        echo "==================================="
        echo "  MacroHard is running!"
        echo "==================================="
        echo ""
        echo "Access the application:"
        echo "  URL: http://localhost:5001"
        echo ""
        echo "Demo credentials:"
        echo "  Email: demo@macrohard.local"
        echo "  Password: demo123!"
        echo ""
        echo "The demo includes 4 sample projects with realistic"
        echo "security vulnerabilities to explore."
        echo ""
        echo "To stop: docker-compose down"
        echo "To view logs: docker-compose logs -f"
        ;;
        
    2)
        echo ""
        echo "Starting MacroHard in PRODUCTION mode..."
        echo ""
        
        # Run setup script
        if [ -f setup.sh ]; then
            chmod +x setup.sh
            ./setup.sh
        else
            echo "Setup script not found. Creating .env file..."
            read -p "Enter a secure SECRET_KEY (or press Enter to generate): " SECRET_KEY
            if [ -z "$SECRET_KEY" ]; then
                SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
            fi
            
            read -p "Enter a secure ENCRYPTION_KEY (or press Enter to generate): " ENCRYPTION_KEY
            if [ -z "$ENCRYPTION_KEY" ]; then
                ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
            fi
            
            cat > .env <<EOF
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
DATABASE_URL=sqlite:///instance/macrohard.db
FLASK_ENV=production
DEMO_MODE=false
EOF
        fi
        
        # Start
        docker-compose up -d --build
        
        echo ""
        echo "==================================="
        echo "  MacroHard is running!"
        echo "==================================="
        echo ""
        echo "Access the application:"
        echo "  URL: http://localhost:5001"
        echo ""
        echo "Default admin credentials:"
        echo "  Email: admin@macrohard.local"
        echo "  Password: ChangeMe123!"
        echo ""
        echo "IMPORTANT: Change the default password immediately!"
        echo ""
        echo "To stop: docker-compose down"
        echo "To view logs: docker-compose logs -f"
        ;;
        
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "Happy analyzing!"
