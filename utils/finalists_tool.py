"""
Finalistes et candidats du concours AES (1997-2000).

Blowfish (candidat anterieur, tres utilise, precurseur de Twofish) est
delegue a PyCryptodome. Camellia (co-developpe Mitsubishi/NTT, retenu par
CRYPTREC et l'ISO/IEC 18033-3, toujours en usage au Japon) n'existe PAS dans
PyCryptodome (`Crypto.Cipher` n'expose que Blowfish parmi les candidats et
finalistes de l'epoque) — delegue a `pyca/cryptography`, deja une dependance
du projet depuis ChaCha20-Poly1305.

Twofish et Serpent (finalistes retenus du concours, tous deux battus par
Rijndael/AES en 2000) n'ont d'implementation dans aucune des deux
bibliotheques disponibles ici ; ils restent une dette explicite (voir
SPRINTS.md Sprint 5).

Meme derivation de cle (PBKDF2-HMAC-SHA256) et mode CBC + PKCS#7 que 3DES : la
couche production ne reimplemente rien.
"""

import os

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from registry.errors import DecryptionFailed, InvalidInput
from utils.hash_tool import pbkdf2_derive

KDF_ITERATIONS = 200_000
SALT_SIZE = 16
CAMELLIA_BLOCK_SIZE = 16  # octets


def _derive(key_string: str, key_size: int, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key_bytes = pbkdf2_derive(key_string, salt, iterations=KDF_ITERATIONS, dklen=key_size)
    return key_bytes, salt


# --- Blowfish (PyCryptodome) ---------------------------------------------------

def encrypt_blowfish_cbc(plain_text: str, key: str) -> dict:
    """Blowfish-CBC, cle de 16 octets (128 bits) derivee par PBKDF2."""
    key_bytes, salt = _derive(key, key_size=16)
    padded = pad(plain_text.encode("utf-8"), Blowfish.block_size)
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(padded)
    return {"cipher_hex": ciphertext.hex(), "iv_hex": cipher.iv.hex(), "salt_hex": salt.hex()}


def decrypt_blowfish_cbc(cipher_hex: str, key: str, iv_hex: str, salt_hex: str) -> str:
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput("cipher_hex, iv_hex et salt_hex doivent etre hexadecimaux.") from exc

    key_bytes, _ = _derive(key, key_size=16, salt=salt_bytes)
    try:
        cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv=iv_bytes)
        decrypted_bytes = unpad(cipher.decrypt(cipher_bytes), Blowfish.block_size)
    except (ValueError, KeyError) as exc:
        raise DecryptionFailed("Echec du dechiffrement Blowfish : bourrage invalide ou cle incorrecte.") from exc

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionFailed("Le dechiffrement Blowfish a reussi mais le resultat n'est pas UTF-8.") from exc


def blowfish_ecb_block_hex(key_hex: str, plaintext_hex: str) -> dict:
    """Chiffre un bloc de 8 octets en Blowfish-ECB, cle et clair en hexadecimal brut (vecteurs)."""
    try:
        key_bytes = bytes.fromhex(key_hex)
        plain_bytes = bytes.fromhex(plaintext_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex et plaintext_hex doivent etre hexadecimaux.") from exc
    if len(plain_bytes) != Blowfish.block_size:
        raise InvalidInput(f"plaintext_hex doit representer exactement {Blowfish.block_size} octets.")
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
    return {"cipher_hex": cipher.encrypt(plain_bytes).hex()}


# --- Camellia (pyca/cryptography) ----------------------------------------------

def encrypt_camellia_cbc(plain_text: str, key: str) -> dict:
    """Camellia-128-CBC, cle de 16 octets derivee par PBKDF2."""
    key_bytes, salt = _derive(key, key_size=16)
    iv_bytes = os.urandom(CAMELLIA_BLOCK_SIZE)

    padder = PKCS7(CAMELLIA_BLOCK_SIZE * 8).padder()
    padded = padder.update(plain_text.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.Camellia(key_bytes), modes.CBC(iv_bytes)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {"cipher_hex": ciphertext.hex(), "iv_hex": iv_bytes.hex(), "salt_hex": salt.hex()}


def decrypt_camellia_cbc(cipher_hex: str, key: str, iv_hex: str, salt_hex: str) -> str:
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput("cipher_hex, iv_hex et salt_hex doivent etre hexadecimaux.") from exc
    if len(iv_bytes) != CAMELLIA_BLOCK_SIZE or not cipher_bytes or len(cipher_bytes) % CAMELLIA_BLOCK_SIZE != 0:
        raise InvalidInput("iv_hex doit faire 16 octets, cipher_hex un multiple non vide de 16.")

    key_bytes, _ = _derive(key, key_size=16, salt=salt_bytes)
    try:
        decryptor = Cipher(algorithms.Camellia(key_bytes), modes.CBC(iv_bytes)).decryptor()
        padded = decryptor.update(cipher_bytes) + decryptor.finalize()
        unpadder = PKCS7(CAMELLIA_BLOCK_SIZE * 8).unpadder()
        decrypted_bytes = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise DecryptionFailed("Echec du dechiffrement Camellia : bourrage invalide ou cle incorrecte.") from exc

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionFailed("Le dechiffrement Camellia a reussi mais le resultat n'est pas UTF-8.") from exc


def camellia_ecb_block_hex(key_hex: str, plaintext_hex: str) -> dict:
    """Chiffre un bloc de 16 octets en Camellia-128-ECB, cle et clair en hexadecimal brut (vecteurs)."""
    try:
        key_bytes = bytes.fromhex(key_hex)
        plain_bytes = bytes.fromhex(plaintext_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex et plaintext_hex doivent etre hexadecimaux.") from exc
    if len(plain_bytes) != CAMELLIA_BLOCK_SIZE:
        raise InvalidInput(f"plaintext_hex doit representer exactement {CAMELLIA_BLOCK_SIZE} octets.")
    encryptor = Cipher(algorithms.Camellia(key_bytes), modes.ECB()).encryptor()
    return {"cipher_hex": (encryptor.update(plain_bytes) + encryptor.finalize()).hex()}
