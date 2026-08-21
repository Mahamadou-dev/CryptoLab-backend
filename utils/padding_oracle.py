"""
Bourrage PKCS#7 et laboratoire d'attaque par oracle de bourrage.

Couche strictement pedagogique : la cle et l'IV sont fournis en clair par
l'appelant (jamais ainsi en production), et le serveur joue volontairement le
role d'un "oracle" qui ne repond que par vrai/faux a la question "ce
dechiffrement a-t-il un bourrage PKCS#7 valide ?" — exactement la fuite
d'information qui a permis l'attaque de Vaudenay (2002) contre CBC, et qui a
depuis motive le passage aux modes authentifies (GCM, Poly1305).

PKCS#7 (RFC 5652 §6.3) bourre un message a un multiple de la taille de bloc en
ajoutant N octets de valeur N (N entre 1 et la taille de bloc). Un bourrage
valide se termine donc toujours par un ou plusieurs octets identiques dont la
valeur egale leur nombre.
"""

from __future__ import annotations

from Crypto.Cipher import AES

from registry.errors import InvalidInput

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Bourre `data` a un multiple de `block_size` (RFC 5652 §6.3)."""
    if not 1 <= block_size <= 255:
        raise InvalidInput("La taille de bloc doit etre entre 1 et 255 octets.")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Retire le bourrage PKCS#7 et le valide.

    Leve `InvalidInput` si le bourrage est absent ou incoherent : c'est
    exactement la reponse binaire (bourrage valide / invalide) qu'un oracle de
    bourrage laisse fuiter, et que l'attaque exploite octet par octet.
    """
    if not data or len(data) % block_size != 0:
        raise InvalidInput("Les donnees bourrees doivent etre un multiple non vide de la taille de bloc.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or pad_len > len(data):
        raise InvalidInput("Bourrage PKCS#7 invalide : octet de fin hors bornes.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise InvalidInput("Bourrage PKCS#7 invalide : les octets de fin ne sont pas homogenes.")
    return data[:-pad_len]


def has_valid_padding(key_bytes: bytes, iv_bytes: bytes, cipher_bytes: bytes) -> bool:
    """
    L'oracle lui-meme : dechiffre en CBC et rapporte seulement si le bourrage
    est valide, jamais le texte. C'est ce bit d'information, repete des
    centaines de fois avec des IV modifies bit a bit, qui suffit a
    l'attaquant pour retrouver le clair entier sans jamais connaitre la cle.
    """
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    decrypted = cipher.decrypt(cipher_bytes)
    try:
        pkcs7_unpad(decrypted, BLOCK_SIZE)
        return True
    except InvalidInput:
        return False


def encrypt_for_oracle(key_hex: str, iv_hex: str, plaintext: str) -> dict:
    """Chiffre un texte en AES-CBC avec bourrage PKCS#7, cle et IV en clair (labo)."""
    try:
        key_bytes = bytes.fromhex(key_hex)
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex et iv_hex doivent etre hexadecimaux.") from exc
    if len(key_bytes) not in (16, 24, 32):
        raise InvalidInput("La cle doit faire 16, 24 ou 32 octets.")
    if len(iv_bytes) != BLOCK_SIZE:
        raise InvalidInput(f"L'IV doit faire {BLOCK_SIZE} octets.")

    padded = pkcs7_pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    return {"cipher_hex": cipher.encrypt(padded).hex(), "block_count": len(padded) // BLOCK_SIZE}


def oracle_query(key_hex: str, iv_hex: str, cipher_hex: str) -> dict:
    """Une seule question posee a l'oracle : ce couple (IV, chiffre) a-t-il un bourrage valide ?"""
    try:
        key_bytes = bytes.fromhex(key_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        cipher_bytes = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex, iv_hex et cipher_hex doivent etre hexadecimaux.") from exc
    if len(iv_bytes) != BLOCK_SIZE or len(cipher_bytes) % BLOCK_SIZE != 0 or not cipher_bytes:
        raise InvalidInput("iv_hex doit faire 16 octets, cipher_hex un multiple non vide de 16.")
    return {"padding_valid": has_valid_padding(key_bytes, iv_bytes, cipher_bytes)}


def _recover_block(key_bytes: bytes, prev_block: bytes, target_block: bytes) -> bytes:
    """
    Recupere le clair d'UN bloc en n'interrogeant que l'oracle de bourrage.

    Principe (Vaudenay) : dechiffrer(target_block) XOR IV_modifie = clair.
    Pour l'octet de poids le plus faible (position 16), on essaie les 256
    valeurs d'un IV forge jusqu'a ce que le bourrage soit valide (bourrage
    `\\x01` le plus souvent) ; cela revele l'octet intermediaire
    D = dechiffrer(target_block)[15], d'ou clair[15] = D XOR prev_block[15].
    On repete en forcant un bourrage `\\x02\\x02`, etc., jusqu'a l'octet 0.
    """
    intermediate = bytearray(BLOCK_SIZE)
    plain = bytearray(BLOCK_SIZE)

    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_value = BLOCK_SIZE - pos
        forged_iv = bytearray(BLOCK_SIZE)
        for i in range(pos + 1, BLOCK_SIZE):
            forged_iv[i] = intermediate[i] ^ pad_value

        found = False
        for guess in range(256):
            forged_iv[pos] = guess
            if has_valid_padding(key_bytes, bytes(forged_iv), target_block):
                # Cas limite : si pos == 15, un faux positif existe quand le
                # bourrage naturel `\x02` deux octets avant la fin coincide.
                # On le leve en perturbant l'octet precedent et en revalidant.
                if pos == BLOCK_SIZE - 1:
                    probe_iv = bytearray(forged_iv)
                    probe_iv[pos - 1] ^= 0xFF
                    if not has_valid_padding(key_bytes, bytes(probe_iv), target_block):
                        continue
                intermediate[pos] = guess ^ pad_value
                plain[pos] = intermediate[pos] ^ prev_block[pos]
                found = True
                break
        if not found:
            raise InvalidInput("L'attaque a echoue a retrouver un octet : oracle incoherent.")

    return bytes(plain)


def padding_oracle_attack(key_hex: str, iv_hex: str, cipher_hex: str) -> dict:
    """
    Dechiffre entierement un texte AES-CBC en n'utilisant QUE l'oracle de
    bourrage — jamais la cle directement, bien qu'elle soit passee ici pour
    simuler les requetes repetees a un serveur reel (l'attaquant, lui, ne la
    connait jamais). Illustre pourquoi un mode non authentifie qui distingue
    "bourrage invalide" de "dechiffrement reussi" est une faille exploitable
    a distance, meme sans jamais casser AES lui-meme.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        cipher_bytes = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise InvalidInput("key_hex, iv_hex et cipher_hex doivent etre hexadecimaux.") from exc
    if len(iv_bytes) != BLOCK_SIZE or len(cipher_bytes) % BLOCK_SIZE != 0 or not cipher_bytes:
        raise InvalidInput("iv_hex doit faire 16 octets, cipher_hex un multiple non vide de 16.")

    blocks = [cipher_bytes[i:i + BLOCK_SIZE] for i in range(0, len(cipher_bytes), BLOCK_SIZE)]
    prev_blocks = [iv_bytes] + blocks[:-1]

    recovered = b"".join(
        _recover_block(key_bytes, prev, block) for prev, block in zip(prev_blocks, blocks, strict=True)
    )
    plain_bytes = pkcs7_unpad(recovered, BLOCK_SIZE)
    return {"plain": plain_bytes.decode("utf-8", errors="replace"), "queries_estimate": 256 * BLOCK_SIZE * len(blocks)}
