
import os

from Crypto.Cipher import AES

from registry.errors import DecryptionFailed, InvalidInput
from utils.hash_tool import pbkdf2_derive

# Nombre d'iterations PBKDF2 pour la derivation de cle. 200 000 est dans la
# fourchette recommandee (OWASP, 2023) pour HMAC-SHA256 ; assez pour ralentir
# une recherche exhaustive hors ligne, assez peu pour rester instantane pour
# un seul utilisateur legitime.
KDF_ITERATIONS = 200_000
SALT_SIZE = 16


def get_aes_key(key_string: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive une cle AES-256 (32 octets) a partir d'une phrase secrete par
    PBKDF2-HMAC-SHA256, avec un sel aleatoire de 16 octets si aucun n'est
    fourni.

    Avant, cette fonction faisait `SHA256(phrase)` : un hash nu, sans sel ni
    etirement. Consequence directe, deux failles distinctes :
      - **pas de sel** : deux utilisateurs avec la meme phrase secrete
        obtiennent la meme cle, et une table precalculee (rainbow table) casse
        tout le monde a la fois ;
      - **pas d'etirement** : un GPU calcule des milliards de SHA-256 par
        seconde, donc autant d'essais de phrase secrete par seconde en
        recherche exhaustive.
    PBKDF2 corrige les deux : le sel rend chaque derivation unique, et les
    200 000 iterations rendent chaque essai couteux.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key_bytes = pbkdf2_derive(key_string, salt, iterations=KDF_ITERATIONS, dklen=32)
    return key_bytes, salt


def encrypt_aes_gcm(plain_text: str, key: str) -> dict:
    """
    Chiffre le texte en utilisant AES-GCM (AES-256).
    Retourne un dictionnaire avec les composants nécessaires
    au déchiffrement, encodés en hexadécimal — y compris le sel PBKDF2, sans
    lequel le destinataire ne peut pas retrouver la meme cle.
    """
    key_bytes, salt = get_aes_key(key)
    plain_bytes = plain_text.encode('utf-8')

    # Créer un nouveau cipher AES-GCM
    # Le nonce est généré automatiquement et est unique
    cipher = AES.new(key_bytes, AES.MODE_GCM)

    # Chiffrer et authentifier
    ciphertext, tag = cipher.encrypt_and_digest(plain_bytes)

    # Le nonce est nécessaire pour le déchiffrement
    nonce = cipher.nonce

    # Retourner toutes les pièces en hexadécimal pour le transport JSON
    return {
        "cipher_hex": ciphertext.hex(),
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "salt_hex": salt.hex(),
    }


def decrypt_aes_gcm(cipher_hex: str, key: str, nonce_hex: str, tag_hex: str, salt_hex: str) -> str:
    """
    Déchiffre le texte AES-GCM.

    Lève `DecryptionFailed` si la vérification du tag échoue. GCM est un mode
    *authentifié* : il ne peut structurellement pas distinguer « mauvaise clé »
    de « données altérées », et c'est une propriété, pas une lacune — le message
    d'erreur le dit plutôt que de le masquer.
    """
    try:
        # Décoder les composants hexadécimaux en octets
        cipher_bytes = bytes.fromhex(cipher_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        tag_bytes = bytes.fromhex(tag_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput(
            "Les champs cipher_hex, nonce_hex, tag_hex et salt_hex doivent etre hexadecimaux."
        ) from exc

    key_bytes, _ = get_aes_key(key, salt=salt_bytes)

    try:
        # Initialiser le cipher avec la clé et le nonce
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)

        # Tenter de déchiffrer ET vérifier le tag d'authentification
        decrypted_bytes = cipher.decrypt_and_verify(cipher_bytes, tag_bytes)
    except (ValueError, KeyError) as exc:
        raise DecryptionFailed(
            "Echec du dechiffrement : le tag d'authentification ne correspond pas. "
            "La cle est incorrecte, ou les donnees ont ete modifiees — AES-GCM ne "
            "permet pas de distinguer les deux."
        ) from exc

    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise DecryptionFailed(
            "Le dechiffrement a reussi mais le resultat n'est pas du texte UTF-8."
        ) from exc
