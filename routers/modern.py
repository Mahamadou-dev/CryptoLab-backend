from fastapi import APIRouter

from db import crud
from db.models import AesDecryptInput, DesDecryptInput, KeyTextInput
from utils import aes_tool, des_tool

router = APIRouter(prefix="/api/modern", tags=["Modern & Historic Symmetric"])


# --- AES ---

@router.post("/aes/encrypt", summary="Encrypt text using AES-256-GCM")
def aes_encrypt_route(data: KeyTextInput):
    result = aes_tool.encrypt_aes_gcm(data.text, data.key)
    crud.record_usage("aes-gcm", "encrypt", len(data.text))
    return {"algorithm": "aes-gcm", "action": "encrypt", **result}


@router.post("/aes/decrypt", summary="Decrypt text from AES-256-GCM")
def aes_decrypt_route(data: AesDecryptInput):
    plain_text = aes_tool.decrypt_aes_gcm(
        data.cipher_hex, data.key, data.nonce_hex, data.tag_hex
    )
    crud.record_usage("aes-gcm", "decrypt", len(data.cipher_hex))

    if plain_text.startswith("Erreur"):
        return {"algorithm": "aes-gcm", "action": "decrypt", "success": False, "error": plain_text}
    return {"algorithm": "aes-gcm", "action": "decrypt", "success": True, "plain": plain_text}


# --- DES ---

@router.post("/des/encrypt", summary="Encrypt text using DES-CBC")
def des_encrypt_route(data: KeyTextInput):
    result = des_tool.encrypt_des_cbc(data.text, data.key)
    crud.record_usage("des-cbc", "encrypt", len(data.text))
    return {"algorithm": "des-cbc", "action": "encrypt", **result}


@router.post("/des/decrypt", summary="Decrypt text from DES-CBC")
def des_decrypt_route(data: DesDecryptInput):
    plain_text = des_tool.decrypt_des_cbc(data.cipher_hex, data.key, data.iv_hex)
    crud.record_usage("des-cbc", "decrypt", len(data.cipher_hex))

    if plain_text.startswith("Erreur"):
        return {"algorithm": "des-cbc", "action": "decrypt", "success": False, "error": plain_text}
    return {"algorithm": "des-cbc", "action": "decrypt", "success": True, "plain": plain_text}
