"""
Substitution mono-alphabetique : ROT13, Atbash, et substitution generale a
alphabet permute.

Contrairement a Cesar (decalage uniforme) et Vigenere (decalage variable par
cle repetee), ces trois algorithmes remplacent chaque lettre par une autre
lettre fixe, choisie par une table de correspondance plutot qu'un calcul.
"""

from __future__ import annotations

import string

from registry.errors import InvalidKey

ALPHABET_UPPER = string.ascii_uppercase
ALPHABET_LOWER = string.ascii_lowercase


def _substitute(text: str, mapping_upper: str) -> str:
    """Applique une table de substitution de 26 lettres, casse preservee."""
    mapping_lower = mapping_upper.lower()
    table_upper = str.maketrans(ALPHABET_UPPER, mapping_upper)
    table_lower = str.maketrans(ALPHABET_LOWER, mapping_lower)
    result = []
    for char in text:
        if char.isupper():
            result.append(char.translate(table_upper))
        elif char.islower():
            result.append(char.translate(table_lower))
        else:
            result.append(char)
    return "".join(result)


def rot13(text: str) -> str:
    """ROT13 : Cesar a decalage 13, son propre inverse (26 / 2 = 13)."""
    mapping = ALPHABET_UPPER[13:] + ALPHABET_UPPER[:13]
    return _substitute(text, mapping)


def atbash(text: str) -> str:
    """Atbash : A<->Z, B<->Y, ... L'alphabet hebraique original, applique ici a Z26."""
    mapping = ALPHABET_UPPER[::-1]
    return _substitute(text, mapping)


def _normalize_key(key: str) -> str:
    """
    Valide que `key` est une permutation des 26 lettres de A a Z (ordre libre,
    casse ignoree) et la renvoie en majuscules.
    """
    upper = key.strip().upper()
    if len(upper) != 26 or set(upper) != set(ALPHABET_UPPER):
        raise InvalidKey(
            "La cle doit contenir chacune des 26 lettres de l'alphabet exactement une fois."
        )
    return upper


def substitution_encrypt(text: str, key: str) -> str:
    """Chiffre par substitution generale : A->key[0], B->key[1], ..."""
    mapping = _normalize_key(key)
    return _substitute(text, mapping)


def substitution_decrypt(text: str, key: str) -> str:
    """Dechiffre : inverse la permutation, puis re-applique la substitution."""
    mapping = _normalize_key(key)
    inverse = [""] * 26
    for plain_letter, cipher_letter in zip(ALPHABET_UPPER, mapping, strict=True):
        inverse[ALPHABET_UPPER.index(cipher_letter)] = plain_letter
    return _substitute(text, "".join(inverse))


def substitution_table(key: str) -> dict[str, str]:
    """Table clair -> chiffre, pour l'affichage pas a pas."""
    mapping = _normalize_key(key)
    return dict(zip(ALPHABET_UPPER, mapping, strict=True))
