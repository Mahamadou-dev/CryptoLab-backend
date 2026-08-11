from fastapi import APIRouter

from db import crud
from db.models import RsaDecryptInput, RsaEncryptInput
from utils import rsa_tool

router = APIRouter(prefix="/api/asymmetric", tags=["Asymmetric"])


@router.get("/rsa/generate-keys", summary="Generate a new RSA 2048-bit key pair")
def rsa_generate_keys():
    keys = rsa_tool.generate_rsa_keys()
    crud.record_usage("rsa-2048", "generate-keys", 0)
    return {"algorithm": "rsa-2048", **keys}


@router.post("/rsa/encrypt", summary="Encrypt text using an RSA public key")
def rsa_encrypt_route(data: RsaEncryptInput):
    cipher_hex = rsa_tool.encrypt_rsa(data.text, data.public_key)
    crud.record_usage("rsa-oaep", "encrypt", len(data.text))

    if cipher_hex.startswith("Erreur"):
        return {"algorithm": "rsa-oaep", "action": "encrypt", "success": False, "error": cipher_hex}
    return {"algorithm": "rsa-oaep", "action": "encrypt", "success": True, "cipher_hex": cipher_hex}


@router.post("/rsa/decrypt", summary="Decrypt text using an RSA private key")
def rsa_decrypt_route(data: RsaDecryptInput):
    plain_text = rsa_tool.decrypt_rsa(data.cipher_hex, data.private_key)
    crud.record_usage("rsa-oaep", "decrypt", len(data.cipher_hex))

    if plain_text.startswith("Erreur"):
        return {"algorithm": "rsa-oaep", "action": "decrypt", "success": False, "error": plain_text}
    return {"algorithm": "rsa-oaep", "action": "decrypt", "success": True, "plain": plain_text}
