import os
from pathlib import Path
import dotenv

def load_env():
    """
    Load environment variables from .env file if it exists
    """
    env_path = Path(".") / ".env"
    if env_path.exists():
        dotenv.load_dotenv(dotenv_path=env_path)
    
    required_vars = ["OPENAI_API_KEY"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print("Warning: The following required environment variables are not set:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables in your environment or in a .env file.")
        print("Example .env file content:")
        print("OPENAI_API_KEY=your-api-key-here") 