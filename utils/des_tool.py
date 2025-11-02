from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


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
    """
    key_bytes = get_des_key(key)

    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)

        cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv_bytes)

        # Déchiffrer
        decrypted_padded_bytes = cipher.decrypt(cipher_bytes)

        # Enlever le padding
        decrypted_bytes = unpad(decrypted_padded_bytes, DES.block_size)

        return decrypted_bytes.decode('utf-8')

    except (ValueError, KeyError):
        # ValueError est levé si le padding est incorrect
        # (indique une mauvaise clé ou un mauvais IV)
        return "Erreur: Échec du déchiffrement. Clé ou IV incorrect."
    except Exception as e:
        return f"Erreur inattendue: {str(e)}"