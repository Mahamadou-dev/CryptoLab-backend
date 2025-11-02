from fastapi import APIRouter
from utils import caesar, vigenere, playfair
from db.models import CaesarInput, KeyTextInput
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult
from datetime import datetime

router = APIRouter(prefix="/api/classical", tags=["Classical"])


# --- César ---

@router.post("/caesar/encrypt", summary="Encrypt text using Caesar cipher")
def caesar_encrypt_route(data: CaesarInput):
    cipher = caesar.caesar_encrypt(data.text, data.shift)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="caesar", action="encrypt",
            input_text=data.text, output_text=cipher
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "caesar", "action": "encrypt", "cipher": cipher}


@router.post("/caesar/decrypt", summary="Decrypt text from Caesar cipher")
def caesar_decrypt_route(data: CaesarInput):
    plain = caesar.caesar_decrypt(data.text, data.shift)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="caesar", action="decrypt",
            input_text=data.text, output_text=plain
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "caesar", "action": "decrypt", "plain": plain}


# --- Vigenère ---

@router.post("/vigenere/encrypt", summary="Encrypt text using Vigenere cipher")
def vigenere_encrypt_route(data: KeyTextInput):
    cipher = vigenere.vigenere_encrypt(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="vigenere", action="encrypt",
            input_text=data.text, output_text=cipher
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "vigenere", "action": "encrypt", "cipher": cipher}


@router.post("/vigenere/decrypt", summary="Decrypt text from Vigenere cipher")
def vigenere_decrypt_route(data: KeyTextInput):
    plain = vigenere.vigenere_decrypt(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="vigenere", action="decrypt",
            input_text=data.text, output_text=plain
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "vigenere", "action": "decrypt", "plain": plain}


# --- Playfair ---

@router.post("/playfair/encrypt", summary="Encrypt text using Playfair cipher")
def playfair_encrypt_route(data: KeyTextInput):
    cipher = playfair.playfair_encrypt(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="playfair", action="encrypt",
            input_text=data.text, output_text=cipher
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "playfair", "action": "encrypt", "cipher": cipher}


@router.post("/playfair/decrypt", summary="Decrypt text from Playfair cipher")
def playfair_decrypt_route(data: KeyTextInput):
    plain = playfair.playfair_decrypt(data.text, data.key)

    # Stockage
    try:
        crud.save_result(SimulationResult(
            algorithm="playfair", action="decrypt",
            input_text=data.text, output_text=plain
        ))
    except Exception as e:
        print(f"Erreur sauvegarde: {e}")

    return {"algorithm": "playfair", "action": "decrypt", "plain": plain}

