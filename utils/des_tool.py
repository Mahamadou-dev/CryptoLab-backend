import os

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

from registry.errors import DecryptionFailed, InvalidInput
from utils.hash_tool import pbkdf2_derive

KDF_ITERATIONS = 200_000
SALT_SIZE = 16


def get_des_key(key_string: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive une cle DES (8 octets) a partir d'une phrase secrete par
    PBKDF2-HMAC-SHA256, avec un sel aleatoire si aucun n'est fourni.

    Avant, cette fonction faisait `SHA256(phrase)[:8]` : un hash nu tronque,
    sans sel ni etirement — voir `aes_tool.get_aes_key` pour le detail des deux
    faiblesses que cela introduisait. DES lui-meme reste casse par force brute
    depuis 1998 (cle de 56 bits) ; renforcer sa derivation de cle ne le rend
    pas sur, seulement plus rigoureux sur ce que ce projet enseigne.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key_bytes = pbkdf2_derive(key_string, salt, iterations=KDF_ITERATIONS, dklen=8)
    return key_bytes, salt


def encrypt_des_cbc(plain_text: str, key: str) -> dict:
    """
    Chiffre le texte en utilisant DES en mode CBC.
    """
    key_bytes, salt = get_des_key(key)
    plain_bytes = plain_text.encode('utf-8')

    # Appliquer le padding (PKCS7) pour s'adapter aux blocs de 8 octets
    padded_bytes = pad(plain_bytes, DES.block_size)

    # Créer un nouveau cipher DES en mode CBC
    # L'IV est généré aléatoirement
    cipher = DES.new(key_bytes, DES.MODE_CBC)

    # Chiffrer
    ciphertext = cipher.encrypt(padded_bytes)

    # L'IV (iv) est nécessaire pour le déchiffrement
    iv = cipher.iv

    return {
        "cipher_hex": ciphertext.hex(),
        "iv_hex": iv.hex(),
        "salt_hex": salt.hex(),
    }


def decrypt_des_cbc(cipher_hex: str, key: str, iv_hex: str, salt_hex: str) -> str:
    """
    Déchiffre le texte DES-CBC.

    Lève `DecryptionFailed` quand le dépadding échoue. Contrairement à AES-GCM,
    CBC n'est pas authentifié : c'est le padding PKCS#7 qui trahit l'erreur, et
    c'est exactement le signal qu'exploite l'attaque par oracle de padding —
    étudiée en phase 3.
    """
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput(
            "Les champs cipher_hex, iv_hex et salt_hex doivent etre hexadecimaux."
        ) from exc

    key_bytes, _ = get_des_key(key, salt=salt_bytes)

    try:
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv_bytes)
        decrypted_padded_bytes = cipher.decrypt(cipher_bytes)
        decrypted_bytes = unpad(decrypted_padded_bytes, DES.block_size)
    except (ValueError, KeyError) as exc:
        raise DecryptionFailed(
            "Echec du dechiffrement : le bourrage PKCS#7 est invalide. "
            "La cle ou l'IV est incorrect."
        ) from exc

    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise DecryptionFailed(
            "Le dechiffrement a reussi mais le resultat n'est pas du texte UTF-8."
        ) from exc
