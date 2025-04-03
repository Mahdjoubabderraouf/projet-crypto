import os
import secrets
from fastapi import Security, HTTPException, Depends
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv, find_dotenv, set_key

# ...existing code...

def generate_admin_api_key(length=32):
    """
    Generate a secure random API key for admin access and save it to .env file.
    
    Args:
        length: Length of the API key (default: 32)
    
    Returns:
        str: The generated API key
    """
    # Generate a secure random API key
    api_key = secrets.token_hex(length)
    
    # Find the .env file or create one if it doesn't exist
    env_file = find_dotenv()
    if not env_file:
        env_file = os.path.join(os.getcwd(), '.env')
        with open(env_file, 'w') as f:
            f.write("# Environment Variables\n")
    
    # Set the API key in the .env file
    set_key(env_file, 'PKG_API_KEY', api_key)
    
    print(f"Admin API key generated and saved to {env_file}")
    return api_key

def validate_admin_api_key(api_key):
    """
    Validate an admin API key against the one stored in .env file.
    
    Args:
        api_key: The API key to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    # Load environment variables from .env file
    load_dotenv()
    
    # Get the stored API key
    stored_api_key = os.environ.get('PKG_API_KEY')
    
    try: 
        if not stored_api_key:
            print("Warning: No admin API key found in .env file")
            return False
    
        # Direct comparison as used in main.py
        return api_key == stored_api_key
    
    except Exception as e:
        print(f"Error validating API key: {e}")
        return False

# FastAPI dependency function to match the pattern in main.py
api_key_header = APIKeyHeader(name="X-API-KEY")

def get_api_key_dependency(api_key: str = Security(api_key_header)):
    """
    FastAPI dependency for validating API key.
    
    """
    if not validate_admin_api_key(api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key


