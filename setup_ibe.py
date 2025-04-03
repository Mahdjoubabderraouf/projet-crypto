# setup_ibe.py
from charm.toolbox.pairinggroup import PairingGroup
from ibe_service import IBEService
from ibe_pickle import save_with_pickle

group = PairingGroup('SS512')
ibe = IBEService(group)

if __name__ == "__main__":
    params, master_key = ibe.setup()
        

    print("Configuration saved successfully!")