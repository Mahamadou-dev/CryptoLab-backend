from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keys() -> dict:
    """
    Génère une nouvelle paire de clés RSA 2048 bits.
    Retourne les clés au format PEM (texte).
    """
    key = RSA.generate(2048)

    # Exporter la clé privée
    private_key = key.export_key().decode('utf-8')

    # Exporter la clé publique
    public_key = key.publickey().export_key().decode('utf-8')

    return {
        "private_key": private_key,
        "public_key": public_key
    }


def encrypt_rsa(plain_text: str, public_key_str: str) -> str:
    """
    Chiffre un texte avec une clé publique RSA.
    """
    try:
        public_key = RSA.import_key(public_key_str)
        cipher_rsa = PKCS1_OAEP.new(public_key)

        ciphertext = cipher_rsa.encrypt(plain_text.encode('utf-8'))

        return ciphertext.hex()
    except Exception as e:
        return f"Erreur: Clé publique invalide ou texte trop long pour RSA. ({str(e)})"


def decrypt_rsa(cipher_hex: str, private_key_str: str) -> str:
    """
    Déchiffre un texte avec une clé privée RSA.
    """
    try:
        private_key = RSA.import_key(private_key_str)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        cipher_bytes = bytes.fromhex(cipher_hex)

        decrypted_bytes = cipher_rsa.decrypt(cipher_bytes)

        return decrypted_bytes.decode('utf-8')
    except (ValueError, KeyError):
        return "Erreur: Échec du déchiffrement. La clé privée est-elle correcte ?"
    except Exception as e:
        return f"Erreur inattendue: {str(e)}"