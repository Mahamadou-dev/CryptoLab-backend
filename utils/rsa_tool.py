from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from registry.errors import DecryptionFailed, InvalidInput, InvalidKey


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

    Distingue les deux échecs possibles, là où l'ancienne version les
    confondait : une clé illisible n'a rien à voir avec un message trop long.
    """
    try:
        public_key = RSA.import_key(public_key_str)
    except (ValueError, IndexError, TypeError) as exc:
        raise InvalidKey("Cle publique RSA illisible : format PEM attendu.") from exc

    try:
        return PKCS1_OAEP.new(public_key).encrypt(plain_text.encode('utf-8')).hex()
    except ValueError as exc:
        # OAEP réserve 2 * taille_de_hash + 2 octets : sur RSA-2048/SHA-1, il
        # reste 214 octets utiles. RSA ne chiffre pas de gros messages — c'est
        # pourquoi le monde réel chiffre une clé de session, pas le message.
        raise InvalidInput(
            "Message trop long pour cette cle RSA. Le chiffrement asymetrique "
            "sert a proteger une cle de session, pas un texte entier."
        ) from exc


def decrypt_rsa(cipher_hex: str, private_key_str: str) -> str:
    """
    Déchiffre un texte avec une clé privée RSA.
    """
    try:
        private_key = RSA.import_key(private_key_str)
    except (ValueError, IndexError, TypeError) as exc:
        raise InvalidKey("Cle privee RSA illisible : format PEM attendu.") from exc

    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise InvalidInput("Le champ cipher_hex doit etre hexadecimal.") from exc

    try:
        decrypted_bytes = PKCS1_OAEP.new(private_key).decrypt(cipher_bytes)
    except (ValueError, KeyError, TypeError) as exc:
        raise DecryptionFailed(
            "Echec du dechiffrement RSA : la cle privee ne correspond pas au "
            "chiffre fourni."
        ) from exc

    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise DecryptionFailed(
            "Le dechiffrement a reussi mais le resultat n'est pas du texte UTF-8."
        ) from exc
