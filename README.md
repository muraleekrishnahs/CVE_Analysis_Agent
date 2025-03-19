# CVE Analysis Agent

An CVE Analysis Agent for analyzing Common Vulnerabilities and Exposures (CVEs).

## Features

- Search and analyze CVE details
- Generate AI-powered summaries and analyses
- View vulnerability metrics and impact assessments
- Track search history
- Compare similar vulnerabilities

## Setup Instructions

1. Clone this repository to your local machine.

2. Run the setup script to create a virtual environment and install dependencies:

   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. The setup script will create a `.env` file from the template if it doesn't exist. Make sure to edit this file and add your OpenAI API key:

   ```
   OPENAI_API_KEY=your_api_key_here
   ```

## Running the Application

1. Activate the virtual environment:

   - On Linux/Mac:
     ```bash
     source venv/bin/activate
     ```
   
   - On Windows:
     ```bash
     source venv/Scripts/activate
     ```

2. Launch the web interface with Streamlit:

   ```bash
   streamlit run app.py
   ```

3. The application will open in your default web browser. If it doesn't open automatically, navigate to http://localhost:8501

## Alternative: Command Line Interface

You can also use the command-line interface to quickly analyze a specific CVE:

```bash
python cve_agent.py CVE-2021-44228
```

## Requirements

- Python 3.8 or higher
- OpenAI API key