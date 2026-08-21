"""
3DES (Triple DES), mode CBC.

3DES applique DES trois fois (Encrypt-Decrypt-Encrypt) avec une cle de 24
octets (K1, K2, K3, "3TDEA"). Sa securite effective n'est PAS 2^168 : une
attaque meet-in-the-middle sur le chiffrement double (2DES) montre qu'un
attaquant qui peut stocker ~2^56 valeurs intermediaires casse le systeme en
temps et memoire de l'ordre de 2^112, pas 2^168 — le cout de la double
application ne s'additionne pas, il se combine. NIST a retire 3DES des
nouveaux usages (SP 800-131A Rev. 2, desapprouve depuis 2023) pour cette
raison et pour la petite taille de bloc (64 bits, vulnerable a l'attaque
Sweet32 par anniversaire au-dela de ~4 Go sous la meme cle).

Conserve ici pour son role historique : la transition du DES simple vers un
chiffrement plus robuste, avant l'arrivee d'AES en 2001.
"""

import os

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from registry.errors import DecryptionFailed, InvalidInput
from utils.hash_tool import pbkdf2_derive

KDF_ITERATIONS = 200_000
SALT_SIZE = 16
KEY_SIZE = 24  # 3TDEA : K1 || K2 || K3, 8 octets chacune


def get_tripledes_key(key_string: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive une cle 3DES (24 octets) par PBKDF2-HMAC-SHA256.

    PyCryptodome refuse une cle degeneree (K1 == K2 ou K2 == K3, qui
    reduirait le systeme a du DES simple ou double) : `DES3.adjust_key_parity`
    et le constructeur levent alors une erreur, traduite ici en `InvalidInput`.
    Avec une cle derivee par PBKDF2, cette collision est statistiquement
    negligeable (probabilite de l'ordre de 2^-64) mais reste possible.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key_bytes = pbkdf2_derive(key_string, salt, iterations=KDF_ITERATIONS, dklen=KEY_SIZE)
    return key_bytes, salt


def encrypt_3des_cbc(plain_text: str, key: str) -> dict:
    """Chiffre le texte en 3DES-CBC (IV aleatoire)."""
    key_bytes, salt = get_tripledes_key(key)
    plain_bytes = plain_text.encode("utf-8")
    padded_bytes = pad(plain_bytes, DES3.block_size)

    try:
        cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    except ValueError as exc:
        raise InvalidInput(
            "La cle derivee est degeneree pour 3DES (K1 ou K2 repetee) : "
            "reessayer avec une autre phrase secrete."
        ) from exc

    ciphertext = cipher.encrypt(padded_bytes)
    return {
        "cipher_hex": ciphertext.hex(),
        "iv_hex": cipher.iv.hex(),
        "salt_hex": salt.hex(),
    }


def decrypt_3des_cbc(cipher_hex: str, key: str, iv_hex: str, salt_hex: str) -> str:
    """Dechiffre un 3DES-CBC. Leve `DecryptionFailed` si le padding est invalide."""
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise InvalidInput(
            "Les champs cipher_hex, iv_hex et salt_hex doivent etre hexadecimaux."
        ) from exc

    key_bytes, _ = get_tripledes_key(key, salt=salt_bytes)

    try:
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv_bytes)
        decrypted_padded = cipher.decrypt(cipher_bytes)
        decrypted_bytes = unpad(decrypted_padded, DES3.block_size)
    except (ValueError, KeyError) as exc:
        raise DecryptionFailed(
            "Echec du dechiffrement 3DES : bourrage PKCS#7 invalide. "
            "La cle ou l'IV est incorrect."
        ) from exc

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionFailed(
            "Le dechiffrement a reussi mais le resultat n'est pas du texte UTF-8."
        ) from exc
