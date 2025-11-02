from fastapi import APIRouter
from utils import caesar, vigenere, playfair
from db.models import CaesarInput, KeyTextInput

router = APIRouter(prefix="/api/classical", tags=["Classical"])

# --- César (mis à jour avec Pydantic) ---

@router.post("/caesar/encrypt", summary="Encrypt text using Caesar cipher")
def caesar_encrypt_route(data: CaesarInput):
    """
    Crypte un texte en utilisant le décalage de César.
    - **text**: Le texte à crypter.
    - **shift**: Le décalage à appliquer (ex: 3).
    """
    cipher = caesar.caesar_encrypt(data.text, data.shift)
    return {"algorithm": "caesar", "action": "encrypt", "cipher": cipher}

@router.post("/caesar/decrypt", summary="Decrypt text from Caesar cipher")
def caesar_decrypt_route(data: CaesarInput):
    """
    Décrypte un texte chiffré par César.
    - **text**: Le texte à décrypter.
    - **shift**: Le décalage utilisé (ex: 3).
    """
    plain = caesar.caesar_decrypt(data.text, data.shift)
    return {"algorithm": "caesar", "action": "decrypt", "plain": plain}


# --- Vigenère (Nouveau) ---

@router.post("/vigenere/encrypt", summary="Encrypt text using Vigenere cipher")
def vigenere_encrypt_route(data: KeyTextInput):
    """
    Crypte un texte en utilisant le chiffre de Vigenère.
    - **text**: Le texte à crypter.
    - **key**: Le mot-clé (ex: "SECRET").
    """
    cipher = vigenere.vigenere_encrypt(data.text, data.key)
    return {"algorithm": "vigenere", "action": "encrypt", "cipher": cipher}

@router.post("/vigenere/decrypt", summary="Decrypt text from Vigenere cipher")
def vigenere_decrypt_route(data: KeyTextInput):
    """
    Décrypte un texte chiffré par Vigenère.
    - **text**: Le texte à décrypter.
    - **key**: Le mot-clé (ex: "SECRET").
    """
    plain = vigenere.vigenere_decrypt(data.text, data.key)
    return {"algorithm": "vigenere", "action": "decrypt", "plain": plain}


# --- Playfair (Nouveau) ---

@router.post("/playfair/encrypt", summary="Encrypt text using Playfair cipher")
def playfair_encrypt_route(data: KeyTextInput):
    """
    Crypte un texte en utilisant le chiffre de Playfair.
    - **text**: Le texte à crypter.
    - **key**: Le mot-clé.
    """
    cipher = playfair.playfair_encrypt(data.text, data.key)
    return {"algorithm": "playfair", "action": "encrypt", "cipher": cipher}

@router.post("/playfair/decrypt", summary="Decrypt text from Playfair cipher")
def playfair_decrypt_route(data: KeyTextInput):
    """
    Décrypte un texte chiffré par Playfair.
    - **text**: Le texte à décrypter.
    - **key**: Le mot-clé.
    """
    plain = playfair.playfair_decrypt(data.text, data.key)
    return {"algorithm": "playfair", "action": "decrypt", "plain": plain}