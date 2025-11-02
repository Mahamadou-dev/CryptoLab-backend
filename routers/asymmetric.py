from fastapi import APIRouter
from utils import rsa_tool
from db.models import RsaEncryptInput, RsaDecryptInput
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult

router = APIRouter(prefix="/api/asymmetric", tags=["Asymmetric"])


@router.get("/rsa/generate-keys", summary="Generate a new RSA 2048-bit key pair")
def rsa_generate_keys():
    # On ne stocke pas la génération de clés
    keys = rsa_tool.generate_rsa_keys()
    return {"algorithm": "rsa-2048", **keys}


@router.post("/rsa/encrypt", summary="Encrypt text using an RSA public key")
def rsa_encrypt_route(data: RsaEncryptInput):
    cipher_hex = rsa_tool.encrypt_rsa(data.text, data.public_key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="rsa-oaep", action="encrypt",
            input_text=data.text, output_text=cipher_hex
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    if "Erreur:" in cipher_hex:
        return {"algorithm": "rsa-oaep", "action": "encrypt", "success": False, "error": cipher_hex}
    else:
        return {"algorithm": "rsa-oaep", "action": "encrypt", "success": True, "cipher_hex": cipher_hex}


@router.post("/rsa/decrypt", summary="Decrypt text using an RSA private key")
def rsa_decrypt_route(data: RsaDecryptInput):
    plain_text = rsa_tool.decrypt_rsa(data.cipher_hex, data.private_key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="rsa-oaep", action="decrypt",
            input_text=data.cipher_hex, output_text=plain_text
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    if "Erreur:" in plain_text:
        return {"algorithm": "rsa-oaep", "action": "decrypt", "success": False, "error": plain_text}
    else:
        return {"algorithm": "rsa-oaep", "action": "decrypt", "success": True, "plain": plain_text}
