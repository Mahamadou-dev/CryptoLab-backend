from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import json


def get_aes_key(key_string: str) -> bytes:
    """
    Crée une clé AES-256 (32 octets) en hachant la clé/phrase
    secrète de l'utilisateur avec SHA-256.
    """
    # .digest() retourne des octets bruts
    return SHA256.new(key_string.encode('utf-8')).digest()


def encrypt_aes_gcm(plain_text: str, key: str) -> dict:
    """
    Chiffre le texte en utilisant AES-GCM (AES-256).
    Retourne un dictionnaire avec les composants nécessaires
    au déchiffrement, encodés en hexadécimal.
    """
    key_bytes = get_aes_key(key)
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
        "tag_hex": tag.hex()
    }


def decrypt_aes_gcm(cipher_hex: str, key: str, nonce_hex: str, tag_hex: str) -> str:
    """
    Déchiffre le texte AES-GCM.
    Lève une exception (ValueError) si l'authentification échoue
    (clé incorrecte ou données corrompues).
    """
    key_bytes = get_aes_key(key)

    try:
        # Décoder les composants hexadécimaux en octets
        cipher_bytes = bytes.fromhex(cipher_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        tag_bytes = bytes.fromhex(tag_hex)

        # Initialiser le cipher avec la clé et le nonce
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)

        # Tenter de déchiffrer ET vérifier le tag d'authentification
        # C'est ici que la magie opère.
        decrypted_bytes = cipher.decrypt_and_verify(cipher_bytes, tag_bytes)

        return decrypted_bytes.decode('utf-8')

    except (ValueError, KeyError):
        # ValueError est levé si le tag ne correspond pas
        # (indique une mauvaise clé ou des données altérées)
        return "Erreur: Échec du déchiffrement. La clé est-elle correcte ou les données ont-elles été modifiées ?"
    except Exception as e:
        return f"Erreur inattendue: {str(e)}"