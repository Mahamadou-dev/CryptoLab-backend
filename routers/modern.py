from fastapi import APIRouter
from utils import aes_tool
from db.models import AesInput, AesDecryptInput
from utils import aes_tool, des_tool  # Ajoute des_tool
from db.models import AesInput, AesDecryptInput, DesInput, DesDecryptInput # Ajoute les modèles DES

router = APIRouter(prefix="/api/modern", tags=["Modern & Historic Symmetric"])


@router.post("/aes/encrypt", summary="Encrypt text using AES-256-GCM")
def aes_encrypt_route(data: AesInput):
    """
    Chiffre un texte avec AES-256-GCM (mode authentifié).
    - **text**: Le texte en clair.
    - **key**: La phrase secrète (sera hachée en clé de 256 bits).

    Retourne le texte chiffré, le nonce, et le tag d'authentification,
    tous encodés en hexadécimal.
    """
    result = aes_tool.encrypt_aes_gcm(data.text, data.key)
    return {
        "algorithm": "aes-gcm",
        "action": "encrypt",
        **result  # Déplie le dict: cipher_hex, nonce_hex, tag_hex
    }


@router.post("/aes/decrypt", summary="Decrypt text from AES-256-GCM")
def aes_decrypt_route(data: AesDecryptInput):
    """
    Déchiffre un texte AES-256-GCM.
    - **cipher_hex**: Le texte chiffré (en hex).
    - **key**: La phrase secrète (utilisée pour régénérer la clé).
    - **nonce_hex**: Le nonce (en hex) fourni lors du chiffrement.
    - **tag_hex**: Le tag d'authentification (en hex) fourni lors du chiffrement.

    Retourne le texte en clair ou un message d'erreur si l'authentification échoue.
    """
    plain_text = aes_tool.decrypt_aes_gcm(
        data.cipher_hex,
        data.key,
        data.nonce_hex,
        data.tag_hex
    )

    if "Erreur:" in plain_text:
        return {
            "algorithm": "aes-gcm",
            "action": "decrypt",
            "success": False,
            "error": plain_text
        }
    else:
        return {
            "algorithm": "aes-gcm",
            "action": "decrypt",
            "success": True,
            "plain": plain_text
        }


@router.post("/des/encrypt", summary="Encrypt text using DES-CBC")
def des_encrypt_route(data: DesInput):
    """
    Chiffre un texte avec DES (mode CBC).
    - **text**: Le texte en clair.
    - **key**: La phrase secrète (sera hachée en clé de 56 bits).

    Retourne le texte chiffré et le vecteur d'initialisation (IV),
    tous deux en hexadécimal.
    """
    result = des_tool.encrypt_des_cbc(data.text, data.key)
    return {
        "algorithm": "des-cbc",
        "action": "encrypt",
        **result  # Déplie le dict: cipher_hex, iv_hex
    }


@router.post("/des/decrypt", summary="Decrypt text from DES-CBC")
def des_decrypt_route(data: DesDecryptInput):
    """
    Déchiffre un texte DES-CBC.
    - **cipher_hex**: Le texte chiffré (en hex).
    - **key**: La phrase secrète.
    - **iv_hex**: Le vecteur d'initialisation (en hex) fourni lors du chiffrement.

    Retourne le texte en clair ou un message d'erreur.
    """
    plain_text = des_tool.decrypt_des_cbc(
        data.cipher_hex,
        data.key,
        data.iv_hex
    )

    if "Erreur:" in plain_text:
        return {"algorithm": "des-cbc", "action": "decrypt", "success": False, "error": plain_text}
    else:
        return {"algorithm": "des-cbc", "action": "decrypt", "success": True, "plain": plain_text}