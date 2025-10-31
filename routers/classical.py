from fastapi import APIRouter
# Ligne correcte
from utils import caesar

router = APIRouter(prefix="/api/classical", tags=["Classical"])

@router.post("/caesar/encrypt")
def caesar_encrypt(data: dict):
    text = data["text"]
    shift = int(data["shift"])
    return {"cipher": caesar.caesar_encrypt(text, shift)}

@router.post("/caesar/decrypt")
def caesar_decrypt(data: dict):
    text = data["text"]
    shift = int(data["shift"])
    return {"plain": caesar.caesar_decrypt(text, shift)}
