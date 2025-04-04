from fastapi import FastAPI, HTTPException, Security, Depends
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from fastapi.security import APIKeyHeader
from auth import get_api_key_dependency
import os
from dotenv import load_dotenv

from models import KeyRequest, APIKeyRequest, EncryptRequest, DecryptRequest
from ibe_service import IBEService
from gt_module import convert_text_to_gt, convert_gt_to_text


# Load environment
load_dotenv()
group = PairingGroup('SS512')

ibe = IBEService(group)

master_key = ibe.deserialize(os.getenv("MASTER_KEY"))
params = ibe.deserialize(os.getenv("PARAMS"))

app = FastAPI()


@app.post("/generate-key")
async def generate_key(
    request: KeyRequest,
    api_key: str =  Depends(get_api_key_dependency)
):
    if api_key != os.getenv("PKG_API_KEY"):
        raise HTTPException(403, detail="Invalid API key")
    
    private_key = ibe.extract_key(params,request.user_id, master_key)
    return {
        "user_id": request.user_id,
        "private_key": ibe.serialize_key(private_key)
    }


@app.post("/encrypt")
async def encrypt_message(
    request: EncryptRequest,
):  
    try:
        
        M_gt= convert_text_to_gt(request.message)
        
        c=ibe.encrypt(params, request.recipient_id, M_gt['gt_element'])
        return{
            "ciphertext": {
                "A": ibe.serialize(c['A']),
                "B": ibe.serialize(c['B']),
                "C": [ibe.serialize(ci) for ci in c['C']]
            }
        }
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

@app.post("/decrypt")
async def decrypt_message(request: DecryptRequest):
    
        # Deserialize the private key
        private_key_dict = request.private_key.dict()  # Convert to dict
        private_key = ibe.deserialize_key(private_key_dict)
        
        
        # Deserialize ciphertext components
        A = ibe.deserialize(request.ciphertext.A)
        B = ibe.deserialize(request.ciphertext.B)
        C = [ibe.deserialize(c) for c in request.ciphertext.C]
        
        print("A", A)
        print("B", B)
        print("C", C)
        
        # Perform decryption
        decrypted = ibe.decrypt(params, private_key, {
            'A': A,
            'B': B,
            'C': C
        })

        
        # Convert decrypted GT element to string
        decrypted_str = convert_gt_to_text(decrypted)
        
        print("decrypted_str", decrypted_str)
        
        # Serialize the result before returning
        return {
            "decrypted": ibe.serialize(decrypted),  # Convert to base64 string
            "status": "success"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)