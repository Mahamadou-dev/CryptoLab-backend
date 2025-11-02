from fastapi import APIRouter
from utils import hash_tool
from db.models import TextInput, BcryptVerifyInput

router = APIRouter(prefix="/api/hash", tags=["Hashing"])

@router.post("/sha256", summary="Generate SHA-256 hash")
def sha256_hash_route(data: TextInput):
    """
    Génère le hash SHA-256 d'un texte.
    - **text**: Le texte à hacher.
    """
    hashed_value = hash_tool.hash_sha256(data.text)
    return {
        "algorithm": "sha256",
        "action": "hash",
        "hash": hashed_value,
        "input": data.text
    }

@router.post("/bcrypt", summary="Generate bcrypt hash (for passwords)")
def bcrypt_hash_route(data: TextInput):
    """
    Génère un hash bcrypt (avec salt) pour un texte.
    Idéal pour stocker des mots de passe.
    - **text**: Le texte/mot de passe à hacher.
    """
    hashed_value = hash_tool.hash_bcrypt(data.text)
    return {
        "algorithm": "bcrypt",
        "action": "hash",
        "hash": hashed_value,
        "note": "Le hash inclut un salt généré aléatoirement. Deux hashs du même texte seront différents."
    }

@router.post("/bcrypt/verify", summary="Verify text against a bcrypt hash")
def bcrypt_verify_route(data: BcryptVerifyInput):
    """
    Vérifie si un texte en clair (ex: mot de passe) correspond
    à un hash bcrypt existant.
    - **text**: Le texte en clair.
    - **hashed_text**: Le hash bcrypt à comparer.
    """
    is_match = hash_tool.verify_bcrypt(data.text, data.hashed_text)
    return {
        "algorithm": "bcrypt",
        "action": "verify",
        "match": is_match,
        "note": "Retourne 'true' si le texte correspond au hash."
    }