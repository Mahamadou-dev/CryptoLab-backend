"""
Modes d'operation d'AES-128 : ECB, CBC, CTR — cle et IV/nonce fournis en
clair (hex), volontairement, pour rejouer des vecteurs deterministes
(NIST SP 800-38A) et pour illustrer la difference entre modes.

C'est une couche strictement pedagogique : en production (`aes_tool.py`),
l'IV/le nonce ne sont *jamais* fournis par l'appelant, ils sont toujours
tires au hasard par le chiffre. Exposer l'IV ici serait une faute grave
ailleurs — le but explicite de ce module est de le rendre visible.
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter

from registry.errors import InvalidInput

BLOCK_SIZE = 16


def _key_and_blocks(key_hex: str, plaintext_hex: str) -> tuple[bytes, bytes]:
    try:
        key_bytes = bytes.fromhex(key_hex)
        plain_bytes = bytes.fromhex(plaintext_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex et plaintext_hex doivent etre hexadecimaux.") from exc
    if len(key_bytes) not in (16, 24, 32):
        raise InvalidInput("La cle doit faire 16, 24 ou 32 octets (AES-128/192/256).")
    if len(plain_bytes) % BLOCK_SIZE != 0:
        raise InvalidInput(
            f"Le texte doit etre un multiple de {BLOCK_SIZE} octets pour ECB/CBC "
            f"(pas de bourrage applique dans ce module pedagogique)."
        )
    return key_bytes, plain_bytes


def encrypt_ecb(key_hex: str, plaintext_hex: str) -> dict:
    """
    ECB (Electronic Codebook) : chaque bloc de 16 octets est chiffre
    independamment, avec la meme cle. Deux blocs de clair identiques donnent
    toujours deux blocs de chiffre identiques — c'est le "pingouin ECB" : le
    motif du clair reste visible dans le chiffre.
    """
    key_bytes, plain_bytes = _key_and_blocks(key_hex, plaintext_hex)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return {"cipher_hex": cipher.encrypt(plain_bytes).hex()}


def encrypt_cbc(key_hex: str, plaintext_hex: str, iv_hex: str) -> dict:
    """
    CBC (Cipher Block Chaining) : chaque bloc de clair est XORe avec le bloc
    de chiffre precedent avant chiffrement (le premier avec l'IV). Deux blocs
    de clair identiques donnent des blocs de chiffre differents des que leur
    contexte (bloc precedent) differe.
    """
    key_bytes, plain_bytes = _key_and_blocks(key_hex, plaintext_hex)
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise InvalidInput("iv_hex doit etre hexadecimal.") from exc
    if len(iv_bytes) != BLOCK_SIZE:
        raise InvalidInput(f"L'IV doit faire {BLOCK_SIZE} octets.")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    return {"cipher_hex": cipher.encrypt(plain_bytes).hex()}


def encrypt_ctr(key_hex: str, plaintext_hex: str, iv_hex: str) -> dict:
    """
    CTR (Counter) : transforme le bloc en chiffrement de flot — un compteur
    initialise a l'IV est chiffre a chaque bloc et XORe avec le clair. Comme
    CBC, deux blocs de clair identiques ne se voient plus dans le chiffre ; en
    plus, CTR ne demande pas de bourrage et est parallelisable.
    """
    key_bytes, plain_bytes = _key_and_blocks(key_hex, plaintext_hex)
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise InvalidInput("iv_hex doit etre hexadecimal.") from exc
    if len(iv_bytes) != BLOCK_SIZE:
        raise InvalidInput(f"Le compteur initial doit faire {BLOCK_SIZE} octets.")
    initial_value = int.from_bytes(iv_bytes, "big")
    ctr = Counter.new(128, initial_value=initial_value)
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    return {"cipher_hex": cipher.encrypt(plain_bytes).hex()}


def ecb_penguin_demo(key_hex: str, block_hex: str, repeats: int) -> dict:
    """
    Repete le meme bloc `repeats` fois et chiffre le resultat en ECB, CBC et
    CTR (IV/nonce fixe a zero pour les deux derniers, choisi ici uniquement
    pour la demonstration). Renvoie les blocs de 16 octets de chaque sortie :
    en ECB, tous les blocs de sortie sont identiques ; en CBC/CTR, non.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
        block_bytes = bytes.fromhex(block_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex et block_hex doivent etre hexadecimaux.") from exc
    if len(block_bytes) != BLOCK_SIZE:
        raise InvalidInput(f"block_hex doit representer exactement {BLOCK_SIZE} octets.")

    plaintext = block_bytes * repeats
    zero_iv = b"\x00" * BLOCK_SIZE

    ecb_out = AES.new(key_bytes, AES.MODE_ECB).encrypt(plaintext)
    cbc_out = AES.new(key_bytes, AES.MODE_CBC, iv=zero_iv).encrypt(plaintext)
    ctr_out = AES.new(key_bytes, AES.MODE_CTR, counter=Counter.new(128, initial_value=0)).encrypt(plaintext)

    def chunks(data: bytes) -> list[str]:
        return [data[i:i + BLOCK_SIZE].hex() for i in range(0, len(data), BLOCK_SIZE)]

    ecb_blocks = chunks(ecb_out)
    cbc_blocks = chunks(cbc_out)
    ctr_blocks = chunks(ctr_out)

    return {
        "plaintext_blocks": chunks(plaintext),
        "ecb_blocks": ecb_blocks,
        "cbc_blocks": cbc_blocks,
        "ctr_blocks": ctr_blocks,
        "ecb_leaks_pattern": len(set(ecb_blocks)) == 1,
        "cbc_leaks_pattern": len(set(cbc_blocks)) == 1,
        "ctr_leaks_pattern": len(set(ctr_blocks)) == 1,
    }
