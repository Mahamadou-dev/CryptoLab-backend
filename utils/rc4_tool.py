"""
RC4 : chiffrement de flot, implemente depuis zero.

CASSE — retire de TLS (RFC 7465, 2015) et deprecie partout ailleurs. Les
octets de debut du flux de cle ne sont pas uniformement aleatoires : un biais
statistique documente affecte notamment le deuxieme octet (biais de Mantin-
Shamir, P(Z2=0) ~= 2/256 au lieu de 1/256), suffisant pour recouvrer des
fragments de texte clair repete sur assez de sessions (attaque pratique contre
les cookies HTTPS chiffres en RC4, 2013). Aucune derivation de cle (PBKDF2)
n'est appliquee ici : contrairement a AES/DES, l'objet de cette page est de
montrer l'algorithme lui-meme, casse, pas de le rendre presentable.

RC4 est un XOR involutif : la meme fonction chiffre et dechiffre.
"""

from registry.errors import InvalidInput


def ksa(key: bytes) -> list[int]:
    """Key-Scheduling Algorithm : initialise la permutation S de 256 octets."""
    if not key:
        raise InvalidInput("La cle RC4 ne peut pas etre vide.")
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def prga(s: list[int], length: int) -> bytes:
    """Pseudo-Random Generation Algorithm : produit `length` octets de flux de cle."""
    s = list(s)
    i = j = 0
    keystream = bytearray(length)
    for n in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        keystream[n] = s[(s[i] + s[j]) % 256]
    return bytes(keystream)


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """Chiffre ou dechiffre `data` : XOR avec le flux de cle genere par KSA+PRGA."""
    s = ksa(key)
    keystream = prga(s, len(data))
    return bytes(d ^ k for d, k in zip(data, keystream, strict=True))


def encrypt_rc4(plain_text: str, key: str) -> dict:
    cipher_bytes = rc4_crypt(plain_text.encode("utf-8"), key.encode("utf-8"))
    return {"cipher_hex": cipher_bytes.hex()}


def decrypt_rc4(cipher_hex: str, key: str) -> str:
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise InvalidInput("Le champ cipher_hex doit etre hexadecimal.") from exc
    plain_bytes = rc4_crypt(cipher_bytes, key.encode("utf-8"))
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        from registry.errors import DecryptionFailed

        raise DecryptionFailed(
            "Le dechiffrement RC4 a produit un resultat non-UTF-8 : la cle est probablement incorrecte."
        ) from exc


def rc4_hex(plaintext_hex: str, key_hex: str) -> dict:
    """Variante hexadecimale : pour rejouer des vecteurs binaires (RFC 6229)."""
    try:
        plain_bytes = bytes.fromhex(plaintext_hex)
        key_bytes = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise InvalidInput("plaintext_hex et key_hex doivent etre hexadecimaux.") from exc
    return {"keystream_hex": rc4_crypt(b"\x00" * len(plain_bytes), key_bytes).hex(),
            "cipher_hex": rc4_crypt(plain_bytes, key_bytes).hex()}
