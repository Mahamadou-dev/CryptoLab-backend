from fastapi import APIRouter

from db import crud
from db.models import BcryptVerifyInput, TextInput
from utils import hash_tool

router = APIRouter(prefix="/api/hash", tags=["Hashing"])


@router.post("/sha256", summary="Generate SHA-256 hash")
def sha256_hash_route(data: TextInput):
    hashed_value = hash_tool.hash_sha256(data.text)
    crud.record_usage("sha256", "hash", len(data.text))
    return {
        "algorithm": "sha256",
        "action": "hash",
        "hash": hashed_value,
        "input": data.text,
    }


@router.post("/bcrypt", summary="Generate bcrypt hash (for passwords)")
def bcrypt_hash_route(data: TextInput):
    hashed_value = hash_tool.hash_bcrypt(data.text)
    crud.record_usage("bcrypt", "hash", len(data.text))
    return {
        "algorithm": "bcrypt",
        "action": "hash",
        "hash": hashed_value,
        "note": "Le hash inclut un salt genere aleatoirement.",
    }


@router.post("/bcrypt/verify", summary="Verify text against a bcrypt hash")
def bcrypt_verify_route(data: BcryptVerifyInput):
    is_match = hash_tool.verify_bcrypt(data.text, data.hashed_text)
    crud.record_usage("bcrypt", "verify", len(data.text))
    return {
        "algorithm": "bcrypt",
        "action": "verify",
        "match": is_match,
        "note": "Retourne 'true' si le texte correspond au hash.",
    }
