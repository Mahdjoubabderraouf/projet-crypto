from charm.toolbox.pairinggroup import PairingGroup
from ibe_service import IBEService
import os

group = PairingGroup('SS512')
ibe = IBEService(group)

if __name__ == "__main__":
    if os.path.exists(".env"):
        print("Error: .env exists. Delete it to reinitialize.")
        exit(1)
        
    params, master_key = ibe.setup()
    
    with open(".env", "w") as f:
        f.write(f"IBE_PARAMS={ibe.serialize(params)}\n")
        f.write(f"IBE_MASTER_KEY={ibe.serialize(master_key)}\n")
        f.write("PKG_API_KEY=your_secure_api_key_here\n")
    
    print("IBE system initialized. .env created with:")
    print("- Public parameters (IBE_PARAMS)")
    print("- Master secret key (IBE_MASTER_KEY)")
    print("- API key (PKG_API_KEY)")