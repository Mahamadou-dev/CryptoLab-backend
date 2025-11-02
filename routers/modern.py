from fastapi import APIRouter
from utils import aes_tool, des_tool
from db.models import AesInput, AesDecryptInput, DesInput, DesDecryptInput, KeyTextInput
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult

router = APIRouter(prefix="/api/modern", tags=["Modern & Historic Symmetric"])


# --- AES ---

@router.post("/aes/encrypt", summary="Encrypt text using AES-256-GCM")
def aes_encrypt_route(data: KeyTextInput):  # Utilise le modèle générique
    result = aes_tool.encrypt_aes_gcm(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="aes-gcm", action="encrypt",
            input_text=data.text, output_text=result.get("cipher_hex", "")
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {
        "algorithm": "aes-gcm",
        "action": "encrypt",
        **result
    }


@router.post("/aes/decrypt", summary="Decrypt text from AES-256-GCM")
def aes_decrypt_route(data: AesDecryptInput):
    plain_text = aes_tool.decrypt_aes_gcm(
        data.cipher_hex, data.key, data.nonce_hex, data.tag_hex
    )

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="aes-gcm", action="decrypt",
            input_text=data.cipher_hex, output_text=plain_text
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    if "Erreur:" in plain_text:
        return {"algorithm": "aes-gcm", "action": "decrypt", "success": False, "error": plain_text}
    else:
        return {"algorithm": "aes-gcm", "action": "decrypt", "success": True, "plain": plain_text}


# --- DES ---

@router.post("/des/encrypt", summary="Encrypt text using DES-CBC")
def des_encrypt_route(data: KeyTextInput):  # Utilise le modèle générique
    result = des_tool.encrypt_des_cbc(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="des-cbc", action="encrypt",
            input_text=data.text, output_text=result.get("cipher_hex", "")
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {
        "algorithm": "des-cbc",
        "action": "encrypt",
        **result
    }


@router.post("/des/decrypt", summary="Decrypt text from DES-CBC")
def des_decrypt_route(data: DesDecryptInput):
    plain_text = des_tool.decrypt_des_cbc(
        data.cipher_hex, data.key, data.iv_hex
    )

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="des-cbc", action="decrypt",
            input_text=data.cipher_hex, output_text=plain_text
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    if "Erreur:" in plain_text:
        return {"algorithm": "des-cbc", "action": "decrypt", "success": False, "error": plain_text}
    else:
        return {"algorithm": "des-cbc", "action": "decrypt", "success": True, "plain": plain_text}

