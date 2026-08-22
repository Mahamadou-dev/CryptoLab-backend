"""
One-Time Pad (masque jetable) sur l'alphabet latin.

Le seul chiffre au secret parfait demontre (Shannon, 1949) — a condition que la
cle soit aussi longue que le message, verrouillee au hasard, et jamais
reutilisee. Ce module applique la troisieme condition par construction (une
cle plus courte que le texte leve une erreur plutot que de boucler dessus,
contrairement a Vigenere) ; les deux premieres restent a la charge de qui
l'utilise — et c'est precisement pourquoi le OTP est correct sur le papier et
inutilisable en pratique.
"""

from __future__ import annotations

from registry.errors import InvalidKey

MODULUS = 26


def _letters_needed(text: str) -> int:
    return sum(1 for char in text if char.isalpha())


def _check_key_length(text: str, key: str) -> None:
    needed = _letters_needed(text)
    if len(key) < needed:
        raise InvalidKey(
            f"La cle ({len(key)} lettres) est plus courte que le message "
            f"({needed} lettres) : le OTP exige une cle au moins aussi longue, "
            "jamais reutilisee."
        )


def otp_encrypt(text: str, key: str) -> str:
    _check_key_length(text, key)
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_index].upper()) - ord("A")
            result.append(chr((ord(char) - base + shift) % MODULUS + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def otp_decrypt(text: str, key: str) -> str:
    _check_key_length(text, key)
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_index].upper()) - ord("A")
            result.append(chr((ord(char) - base - shift) % MODULUS + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)
