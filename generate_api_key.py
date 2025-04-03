#!/usr/bin/env python

import os
from dotenv import load_dotenv
from auth import generate_admin_api_key

def main():
    """
    Check if an API key exists. If not, generate one.
    Display the API key in either case.
    """
    # Load environment variables
    load_dotenv()
    
    # Check if API key exists
    existing_key = os.environ.get('PKG_API_KEY')
    
    if existing_key:
        print("Existing API key found:")
        print(existing_key)
    else:
        print("No API key found. Generating new API key...")
        new_key = generate_admin_api_key()
        print(f"New API key generated: {new_key}")

if __name__ == "__main__":
    main()
