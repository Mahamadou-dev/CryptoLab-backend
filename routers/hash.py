from fastapi import APIRouter
from utils import hash_tool
from db.models import TextInput, BcryptVerifyInput
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult

router = APIRouter(prefix="/api/hash", tags=["Hashing"])


@router.post("/sha256", summary="Generate SHA-256 hash")
def sha256_hash_route(data: TextInput):
    hashed_value = hash_tool.hash_sha256(data.text)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="sha256", action="hash",
            input_text=data.text, output_text=hashed_value
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {
        "algorithm": "sha256",
        "action": "hash",
        "hash": hashed_value,
        "input": data.text
    }


@router.post("/bcrypt", summary="Generate bcrypt hash (for passwords)")
def bcrypt_hash_route(data: TextInput):
    hashed_value = hash_tool.hash_bcrypt(data.text)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="bcrypt", action="hash",
            input_text="[TEXTE CACHÉ]",  # Ne pas stocker le mot de passe en clair
            output_text=hashed_value
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {
        "algorithm": "bcrypt",
        "action": "hash",
        "hash": hashed_value,
        "note": "Le hash inclut un salt généré aléatoirement."
    }


@router.post("/bcrypt/verify", summary="Verify text against a bcrypt hash")
def bcrypt_verify_route(data: BcryptVerifyInput):
    is_match = hash_tool.verify_bcrypt(data.text, data.hashed_text)

    # On ne stocke pas les tentatives de vérification pour le moment

    return {
        "algorithm": "bcrypt",
        "action": "verify",
        "match": is_match,
        "note": "Retourne 'true' si le texte correspond au hash."
    }
