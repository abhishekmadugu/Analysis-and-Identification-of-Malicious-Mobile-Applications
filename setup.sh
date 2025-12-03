#!/bin/bash

# APK Malware Scanner - Setup Script
# This script sets up the development environment for the malware scanner

echo "🔥 APK Malware Scanner - Setup Script"
echo "======================================"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if running on supported system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    SYSTEM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    SYSTEM="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_success "Detected system: $SYSTEM"

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    print_success "Python version: $PYTHON_VERSION"
    
    # Check if Python version is >= 3.8
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        print_success "Python version is compatible"
    else
        print_error "Python 3.8 or higher is required"
        exit 1
    fi
else
    print_error "Python 3 is not installed"
    exit 1
fi

# Install system dependencies
echo ""
echo "📦 Installing system dependencies..."

if [[ "$SYSTEM" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        print_warning "Installing dependencies via apt-get (requires sudo)"
        sudo apt-get update
        sudo apt-get install -y python3-dev python3-pip python3-venv libffi-dev libssl-dev libyara-dev build-essential
    elif command -v yum &> /dev/null; then
        print_warning "Installing dependencies via yum (requires sudo)"
        sudo yum install -y python3-devel python3-pip libffi-devel openssl-devel yara-devel gcc
    elif command -v dnf &> /dev/null; then
        print_warning "Installing dependencies via dnf (requires sudo)"
        sudo dnf install -y python3-devel python3-pip libffi-devel openssl-devel yara-devel gcc
    else
        print_error "No supported package manager found (apt-get, yum, dnf)"
        exit 1
    fi
elif [[ "$SYSTEM" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        print_warning "Installing dependencies via Homebrew"
        brew install yara libffi openssl
    else
        print_error "Homebrew is not installed. Please install it from https://brew.sh/"
        exit 1
    fi
fi

print_success "System dependencies installed"

# Create virtual environment
echo ""
echo "🐍 Setting up Python virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
pip install --upgrade pip
print_success "pip upgraded"

# Install Python dependencies
echo ""
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    print_success "Python dependencies installed"
else
    print_error "Failed to install Python dependencies"
    print_warning "You may need to install YARA manually:"
    print_warning "  - Ubuntu/Debian: sudo apt-get install libyara-dev"
    print_warning "  - CentOS/RHEL: sudo yum install yara-devel"
    print_warning "  - macOS: brew install yara"
    exit 1
fi

# Check if Androguard is working
echo ""
echo "🔧 Testing Androguard installation..."
python3 -c "from androguard.core.bytecodes.apk import APK; print('Androguard is working!')" 2>/dev/null

if [ $? -eq 0 ]; then
    print_success "Androguard is working correctly"
else
    print_warning "Androguard test failed, but this might be normal"
fi

# Check if YARA is working
echo ""
echo "🛡️  Testing YARA installation..."
python3 -c "import yara; print('YARA is working!')" 2>/dev/null

if [ $? -eq 0 ]; then
    print_success "YARA is working correctly"
else
    print_error "YARA installation failed"
    print_warning "Please install YARA system dependencies and try again"
fi

# Set executable permissions
chmod +x app.py

# Create necessary directories
mkdir -p uploads
mkdir -p logs

print_success "Created necessary directories"

# Final instructions
echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "To start the scanner:"
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Start the Flask server:"
echo "   python3 app.py"
echo ""
echo "3. Open your browser and visit:"
echo "   http://localhost:5000"
echo ""
echo "📝 Notes:"
echo "   - Place your APK files in the web interface"
echo "   - YARA rules are in the yara_rules/ directory"
echo "   - Logs will be saved in the logs/ directory"
echo "   - Upload files are temporarily stored in uploads/"
echo ""
print_success "Happy scanning! 🔍"
