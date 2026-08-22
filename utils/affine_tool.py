"""
Chiffre affine : x -> a*x + b (mod 26).

Generalise Cesar (qui est le cas a=1) en ajoutant une multiplication. `a` doit
etre premier avec 26 pour etre inversible — sinon plusieurs lettres claires
retomberaient sur la meme lettre chiffree, et le dechiffrement serait ambigu.
"""

from __future__ import annotations

from registry.errors import InvalidKey

MODULUS = 26


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = _extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(a: int, modulus: int = MODULUS) -> int:
    gcd, x, _ = _extended_gcd(a % modulus, modulus)
    if gcd != 1:
        raise InvalidKey(
            f"'a' ({a}) n'est pas premier avec 26 : le chiffre affine ne serait pas reversible."
        )
    return x % modulus


def affine_encrypt(text: str, a: int, b: int) -> str:
    # Valide 'a' des l'entree : un dechiffrement plus tard echouerait sinon
    # silencieusement sur une cle qui n'aurait jamais du etre acceptee.
    mod_inverse(a)
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            result.append(chr((a * x + b) % MODULUS + base))
        else:
            result.append(char)
    return "".join(result)


def affine_decrypt(text: str, a: int, b: int) -> str:
    a_inv = mod_inverse(a)
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            y = ord(char) - base
            result.append(chr((a_inv * (y - b)) % MODULUS + base))
        else:
            result.append(char)
    return "".join(result)
