import os
import sys
from dotenv import load_dotenv
from auth import validate_admin_api_key

def main():
    """
    Check if there is a valid API key in the environment variables.
    
    Returns:
        int: 0 if a valid API key exists, 1 otherwise
    """
    # Load environment variables from .env file
    load_dotenv()
    
    # Check if PKG_API_KEY exists in environment
    api_key = os.environ.get('PKG_API_KEY')
    
    if not api_key:
        print("No API key found in environment variables")
        return 1
    
    # Validate the API key using the auth module
    if validate_admin_api_key(api_key):
        print(f"API key is valid: {api_key}" )
        return 0
    else:
        print("API key is invalid")
        return 1

if __name__ == "__main__":
    sys.exit(main())
