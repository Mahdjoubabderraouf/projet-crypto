# setup_ibe.py
from charm.toolbox.pairinggroup import PairingGroup
from ibe_service import IBEService
from dotenv import load_dotenv, set_key
import os

# Load environment variables
load_dotenv()

group = PairingGroup('SS512')
ibe = IBEService(group)

if __name__ == "__main__":
    params, master_key = ibe.setup()
    
    # Serialize parameters and master key
    serialized_params = ibe.serialize(params)
    serialized_master_key = ibe.serialize(master_key)
    
    # Update .env file with new values for MASTER_KEY and PARAMS
    set_key(".env", "MASTER_KEY", serialized_master_key)
    set_key(".env", "PARAMS", serialized_params)
    
    print("✅✅✅ Configuration saved successfully ✅✅✅!")
    print("Parameters and master key generated.")
    print("Parameters and master key have been saved to .env file.")
