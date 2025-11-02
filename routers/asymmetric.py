from fastapi import APIRouter
from utils import rsa_tool
from db.models import RsaEncryptInput, RsaDecryptInput

router = APIRouter(prefix="/api/asymmetric", tags=["Asymmetric"])


@router.get("/rsa/generate-keys", summary="Generate a new RSA 2048-bit key pair")
def rsa_generate_keys():
    """
    Génère une nouvelle paire de clés RSA (publique et privée).
    Les clés sont retournées au format PEM (texte).
    """
    keys = rsa_tool.generate_rsa_keys()
    return {
        "algorithm": "rsa-2048",
        **keys
    }


@router.post("/rsa/encrypt", summary="Encrypt text using an RSA public key")
def rsa_encrypt_route(data: RsaEncryptInput):
    """
    Chiffre un texte avec une clé publique RSA.
    - **text**: Le texte en clair (doit être court).
    - **public_key**: La clé publique au format PEM.
    """
    cipher_hex = rsa_tool.encrypt_rsa(data.text, data.public_key)

    if "Erreur:" in cipher_hex:
        return {"algorithm": "rsa-oaep", "action": "encrypt", "success": False, "error": cipher_hex}
    else:
        return {"algorithm": "rsa-oaep", "action": "encrypt", "success": True, "cipher_hex": cipher_hex}


@router.post("/rsa/decrypt", summary="Decrypt text using an RSA private key")
def rsa_decrypt_route(data: RsaDecryptInput):
    """
    Déchiffre un texte avec une clé privée RSA.
    - **cipher_hex**: Le texte chiffré (en hex).
    - **private_key**: La clé privée au format PEM.
    """
    plain_text = rsa_tool.decrypt_rsa(data.cipher_hex, data.private_key)

    if "Erreur:" in plain_text:
        return {"algorithm": "rsa-oaep", "action": "decrypt", "success": False, "error": plain_text}
    else:
        return {"algorithm": "rsa-oaep", "action": "decrypt", "success": True, "plain": plain_text}