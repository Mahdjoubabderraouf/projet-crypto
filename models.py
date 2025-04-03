from pydantic import BaseModel

class KeyRequest(BaseModel):
    user_id: str

class APIKeyRequest(BaseModel):
    name: str
    description: str = ""

class EncryptRequest(BaseModel):
    recipient_id: str
    message: str

class DecryptRequest(BaseModel):
    ciphertext: dict
    private_key: dict  # Serialized private key