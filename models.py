from pydantic import BaseModel
from typing import List

class KeyRequest(BaseModel):
    user_id: str

class APIKeyRequest(BaseModel):
    name: str
    description: str = ""

class EncryptRequest(BaseModel):
    recipient_id: str
    message: str
    

class CiphertextModel(BaseModel):
    A: str
    B: str
    C: List[str]

class PrivateKeyModel(BaseModel):
    d0 : str
    dn : List[str]

class DecryptRequest(BaseModel):
    ciphertext: CiphertextModel
    private_key: PrivateKeyModel