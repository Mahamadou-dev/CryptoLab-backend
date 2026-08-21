"""
ChaCha20-Poly1305 (RFC 8439) : chiffrement de flot authentifie moderne,
standard de TLS 1.3. Delegue entierement a `pyca/cryptography` (couche
production) — il n'y a pas de reimplementation pedagogique ici, comme pour
AES-GCM : la construction interne (permutation ARX, compteur, Poly1305) est
enseignee dans l'article, pas rejouee octet par octet dans ce module.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from registry.errors import DecryptionFailed, InvalidInput
from utils.hash_tool import pbkdf2_derive

KDF_ITERATIONS = 200_000
SALT_SIZE = 16
KEY_SIZE = 32  # ChaCha20 utilise toujours une cle de 256 bits
NONCE_SIZE = 12  # 96 bits, RFC 8439


def get_chacha20_key(key_string: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive une cle de 32 octets par PBKDF2-HMAC-SHA256, comme AES/DES/3DES."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key_bytes = pbkdf2_derive(key_string, salt, iterations=KDF_ITERATIONS, dklen=KEY_SIZE)
    return key_bytes, salt


def encrypt_chacha20(plain_text: str, key: str) -> dict:
    """Chiffre et authentifie le texte en ChaCha20-Poly1305 (nonce aleatoire)."""
    key_bytes, salt = get_chacha20_key(key)
    nonce = os.urandom(NONCE_SIZE)
    aead = ChaCha20Poly1305(key_bytes)
    ciphertext = aead.encrypt(nonce, plain_text.encode("utf-8"), None)
    return {
        "cipher_hex": ciphertext.hex(),
        "nonce_hex": nonce.hex(),
        "salt_hex": salt.hex(),
    }


def decrypt_chacha20(cipher_hex: str, key: str, nonce_hex: str, salt_hex: str) -> str:
    """
    Dechiffre et verifie le tag Poly1305 (les 16 derniers octets de `cipher_hex`).

    Comme AES-GCM, ChaCha20-Poly1305 est un mode authentifie : `InvalidTag`
    signifie « mauvaise cle ou donnees alterees », sans distinction possible.
    """
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput(
            "Les champs cipher_hex, nonce_hex et salt_hex doivent etre hexadecimaux."
        ) from exc

    key_bytes, _ = get_chacha20_key(key, salt=salt_bytes)
    aead = ChaCha20Poly1305(key_bytes)

    try:
        plain_bytes = aead.decrypt(nonce_bytes, cipher_bytes, None)
    except InvalidTag as exc:
        raise DecryptionFailed(
            "Echec du dechiffrement : le tag Poly1305 ne correspond pas. "
            "La cle est incorrecte, ou les donnees ont ete modifiees."
        ) from exc

    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionFailed(
            "Le dechiffrement a reussi mais le resultat n'est pas du texte UTF-8."
        ) from exc


def chacha20_poly1305_raw(key_hex: str, nonce_hex: str, plaintext_hex: str, aad_hex: str = "") -> dict:
    """
    Variante pedagogique deterministe : cle, nonce et associated data fournis
    en clair (hex), pour rejouer le vecteur de test complet RFC 8439 §2.8.2.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        plain_bytes = bytes.fromhex(plaintext_hex)
        aad_bytes = bytes.fromhex(aad_hex) if aad_hex else b""
    except ValueError as exc:
        raise InvalidInput("Les champs hex fournis sont invalides.") from exc

    aead = ChaCha20Poly1305(key_bytes)
    ciphertext_and_tag = aead.encrypt(nonce_bytes, plain_bytes, aad_bytes or None)
    return {
        "cipher_hex": ciphertext_and_tag[:-16].hex(),
        "tag_hex": ciphertext_and_tag[-16:].hex(),
    }
