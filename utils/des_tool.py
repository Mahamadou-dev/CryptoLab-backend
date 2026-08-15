from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from registry.errors import DecryptionFailed, InvalidInput


def get_des_key(key_string: str) -> bytes:
    """
    Crée une clé DES (8 octets) en hachant la clé/phrase
    secrète et en tronquant à 8 octets.
    """
    # Utiliser SHA256 et prendre les 8 premiers octets
    return SHA256.new(key_string.encode('utf-8')).digest()[:8]


def encrypt_des_cbc(plain_text: str, key: str) -> dict:
    """
    Chiffre le texte en utilisant DES en mode CBC.
    """
    key_bytes = get_des_key(key)
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
        "iv_hex": iv.hex()
    }


def decrypt_des_cbc(cipher_hex: str, key: str, iv_hex: str) -> str:
    """
    Déchiffre le texte DES-CBC.

    Lève `DecryptionFailed` quand le dépadding échoue. Contrairement à AES-GCM,
    CBC n'est pas authentifié : c'est le padding PKCS#7 qui trahit l'erreur, et
    c'est exactement le signal qu'exploite l'attaque par oracle de padding —
    étudiée en phase 3.
    """
    key_bytes = get_des_key(key)

    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise InvalidInput("Les champs cipher_hex et iv_hex doivent etre hexadecimaux.") from exc

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
