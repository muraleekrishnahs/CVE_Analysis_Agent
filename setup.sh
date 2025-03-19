echo "Setting up CVE Analysis Agent..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows
    source venv/Scripts/activate
else
    # Linux/Mac
    source venv/bin/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create .env file from example if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit the .env file and add your OpenAI API key."
fi

echo ""
echo "Setup complete! To start using the CVE Analysis Agent:"
echo "1. Activate the virtual environment:"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "   source venv/Scripts/activate"
else
    echo "   source venv/bin/activate"
fi
echo "2. Make sure to set your OpenAI API key in the .env file."
echo ""
echo "3. Run the web interface with:"
echo "   streamlit run app.py"
echo ""
echo "4. Or use the command-line interface:"
echo "   python cve_agent.py CVE-2021-44228"
echo "" 