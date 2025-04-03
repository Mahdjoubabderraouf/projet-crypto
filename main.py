from fastapi import FastAPI, HTTPException, Security, Depends
from charm.toolbox.pairinggroup import PairingGroup
from fastapi.security import APIKeyHeader
from auth import get_api_key_dependency
import os
from dotenv import load_dotenv

from models import KeyRequest, APIKeyRequest, EncryptRequest, DecryptRequest
from ibe_service import IBEService


# Load environment
load_dotenv()
group = PairingGroup('SS512')

ibe = IBEService(group)
params, master_key = ibe.setup()

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
        c=ibe.encrypt(params, request.recipient_id, request.message)
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
    try:
        # Deserialize the private key
        private_key = ibe.deserialize_key(request.private_key)
        
        # Deserialize ciphertext components
        A = ibe.deserialize(request.ciphertext.A)
        B = ibe.deserialize(request.ciphertext.B)
        C = [ibe.deserialize(c) for c in request.ciphertext.C]
        
        # Perform decryption
        decrypted = ibe.decrypt(params, {
            'A': A,
            'B': B,
            'C': C
        }, private_key)
        
        # Serialize the result before returning
        return {
            "decrypted": ibe.serialize(decrypted),  # Convert to base64 string
            "status": "success"
        }
    except ValueError as e:
        raise HTTPException(400, detail="Decryption failed")
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(500, detail="Internal server error")    
    
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)