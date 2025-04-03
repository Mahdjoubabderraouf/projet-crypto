from fastapi import FastAPI, HTTPException, Security
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
params = ibe.load_params_from_env()
params = ibe.deserialize(params)

app = FastAPI()


@app.post("/generate-key")
async def generate_key(
    request: KeyRequest,
    api_key: str =  Depends(get_api_key_dependency)
):
    if api_key != os.getenv("PKG_API_KEY"):
        raise HTTPException(403, detail="Invalid API key")
    
    private_key = ibe.extract_key(request.user_id)
    return {
        "user_id": request.user_id,
        "private_key": ibe.serialize_key(private_key)
    }


@app.post("/encrypt")
async def encrypt_message(
    request: EncryptRequest,
):  
    try:
        c=ibe.encrypt(request.recipient_id, params, request.message)
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
async def decrypt_message(
    request: DecryptRequest,
):
    try:
        decrypted = ibe.decrypt(request.ciphertext, request.private_key)
        return {"message": decrypted}
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)