from fastapi import APIRouter

from db import crud
from db.models import KeyTextInput, ShiftInput
from utils import caesar, columnar, playfair, rail_fence, vigenere

router = APIRouter(prefix="/api/classical", tags=["Classical"])


# --- Cesar ---

@router.post("/caesar/encrypt", summary="Encrypt text using Caesar cipher")
def caesar_encrypt_route(data: ShiftInput):
    cipher = caesar.caesar_encrypt(data.text, data.shift)
    crud.record_usage("caesar", "encrypt", len(data.text))
    return {"algorithm": "caesar", "action": "encrypt", "cipher": cipher}


@router.post("/caesar/decrypt", summary="Decrypt text from Caesar cipher")
def caesar_decrypt_route(data: ShiftInput):
    plain = caesar.caesar_decrypt(data.text, data.shift)
    crud.record_usage("caesar", "decrypt", len(data.text))
    return {"algorithm": "caesar", "action": "decrypt", "plain": plain}


# --- Vigenere ---

@router.post("/vigenere/encrypt", summary="Encrypt text using Vigenere cipher")
def vigenere_encrypt_route(data: KeyTextInput):
    cipher = vigenere.vigenere_encrypt(data.text, data.key)
    crud.record_usage("vigenere", "encrypt", len(data.text))
    return {"algorithm": "vigenere", "action": "encrypt", "cipher": cipher}


@router.post("/vigenere/decrypt", summary="Decrypt text from Vigenere cipher")
def vigenere_decrypt_route(data: KeyTextInput):
    plain = vigenere.vigenere_decrypt(data.text, data.key)
    crud.record_usage("vigenere", "decrypt", len(data.text))
    return {"algorithm": "vigenere", "action": "decrypt", "plain": plain}


# --- Playfair ---

@router.post("/playfair/encrypt", summary="Encrypt text using Playfair cipher")
def playfair_encrypt_route(data: KeyTextInput):
    """
    Note : Playfair ne conserve ni les espaces ni la longueur du message.
    La sortie est un flux de lettres.
    """
    cipher = playfair.playfair_encrypt(data.text, data.key)
    crud.record_usage("playfair", "encrypt", len(data.text))
    return {
        "algorithm": "playfair",
        "action": "encrypt",
        "cipher": cipher,
        "digrams": playfair.build_digrams(data.text),
    }


@router.post("/playfair/decrypt", summary="Decrypt text from Playfair cipher")
def playfair_decrypt_route(data: KeyTextInput):
    """
    Le bourrage 'X' insere au chiffrement est retire. `plain_raw` contient la
    sortie avant nettoyage, car l'heuristique de depadding est ambigue par
    nature (un 'X' du message d'origine peut etre retire).
    """
    plain = playfair.playfair_decrypt(data.text, data.key)
    plain_raw = playfair.playfair_decrypt(data.text, data.key, remove_padding=False)
    crud.record_usage("playfair", "decrypt", len(data.text))
    return {
        "algorithm": "playfair",
        "action": "decrypt",
        "plain": plain,
        "plain_raw": plain_raw,
    }


# --- Rail Fence (zigzag) ---

@router.post("/railfence/encrypt", summary="Encrypt text using the Rail Fence cipher")
def rail_fence_encrypt_route(data: ShiftInput):
    """
    Chiffre un texte en zigzag sur plusieurs rails.

    - **text** : le texte a chiffrer (espaces et ponctuation conserves).
    - **shift** : le nombre de rails (ex: 3).
    """
    cipher = rail_fence.rail_fence_encrypt(data.text, data.shift)
    crud.record_usage("railfence", "encrypt", len(data.text))
    return {"algorithm": "railfence", "action": "encrypt", "cipher": cipher}


@router.post("/railfence/decrypt", summary="Decrypt text from the Rail Fence cipher")
def rail_fence_decrypt_route(data: ShiftInput):
    """
    Dechiffre un texte Rail Fence. Inverse exact du chiffrement.

    - **text** : le texte a dechiffrer.
    - **shift** : le nombre de rails utilise au chiffrement.
    """
    plain = rail_fence.rail_fence_decrypt(data.text, data.shift)
    crud.record_usage("railfence", "decrypt", len(data.text))
    return {"algorithm": "railfence", "action": "decrypt", "plain": plain}


# --- Transposition par colonnes ---

@router.post("/columnar/encrypt", summary="Encrypt text using columnar transposition")
def columnar_encrypt_route(data: KeyTextInput):
    """
    Transposition par colonnes : le texte est ecrit ligne par ligne, les
    colonnes sont relues dans l'ordre alphabetique des lettres de la cle.

    C'est l'algorithme que l'ancienne route `/railfence` implementait
    reellement, sous un nom qui n'etait pas le sien.
    """
    cipher = columnar.columnar_encrypt(data.text, data.key)
    crud.record_usage("columnar", "encrypt", len(data.text))
    return {
        "algorithm": "columnar",
        "action": "encrypt",
        "cipher": cipher,
        "key_order": columnar.key_order(data.key),
    }


@router.post("/columnar/decrypt", summary="Decrypt text from columnar transposition")
def columnar_decrypt_route(data: KeyTextInput):
    plain = columnar.columnar_decrypt(data.text, data.key)
    crud.record_usage("columnar", "decrypt", len(data.text))
    return {
        "algorithm": "columnar",
        "action": "decrypt",
        "plain": plain,
        "key_order": columnar.key_order(data.key),
    }
