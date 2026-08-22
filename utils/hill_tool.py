"""
Chiffre de Hill (2x2) : chaque paire de lettres est un vecteur, multiplie par
une matrice de cle mod 26.

Premier chiffre a melanger plusieurs lettres a la fois par de l'algebre
lineaire plutot que lettre par lettre — la matrice doit etre inversible mod 26
(son determinant premier avec 26) pour que le dechiffrement existe.
"""

from __future__ import annotations

from registry.errors import InvalidInput, InvalidKey

MODULUS = 26


def _mod_inverse(a: int, modulus: int = MODULUS) -> int:
    a %= modulus
    for candidate in range(1, modulus):
        if (a * candidate) % modulus == 1:
            return candidate
    raise InvalidKey(
        f"Le determinant de la matrice ({a}) n'est pas premier avec 26 : "
        "la matrice n'est pas inversible, le dechiffrement n'existerait pas."
    )


def _key_matrix(a: int, b: int, c: int, d: int) -> tuple[tuple[int, int], tuple[int, int]]:
    return ((a, b), (c, d))


def _determinant(matrix: tuple[tuple[int, int], tuple[int, int]]) -> int:
    (a, b), (c, d) = matrix
    return (a * d - b * c) % MODULUS


def _inverse_matrix(
    matrix: tuple[tuple[int, int], tuple[int, int]],
) -> tuple[tuple[int, int], tuple[int, int]]:
    det_inv = _mod_inverse(_determinant(matrix))
    (a, b), (c, d) = matrix
    return (
        ((det_inv * d) % MODULUS, (det_inv * -b) % MODULUS),
        ((det_inv * -c) % MODULUS, (det_inv * a) % MODULUS),
    )


def _clean(text: str) -> str:
    return "".join(char for char in text.upper() if char.isalpha())


def _apply(text: str, matrix: tuple[tuple[int, int], tuple[int, int]]) -> str:
    cleaned = _clean(text)
    if len(cleaned) % 2 == 1:
        cleaned += "X"
    (a, b), (c, d) = matrix
    out = []
    for i in range(0, len(cleaned), 2):
        x = ord(cleaned[i]) - ord("A")
        y = ord(cleaned[i + 1]) - ord("A")
        out.append(chr((a * x + b * y) % MODULUS + ord("A")))
        out.append(chr((c * x + d * y) % MODULUS + ord("A")))
    return "".join(out)


def hill_encrypt(text: str, a: int, b: int, c: int, d: int) -> str:
    matrix = _key_matrix(a, b, c, d)
    _mod_inverse(_determinant(matrix))  # valide la cle avant de chiffrer
    return _apply(text, matrix)


def hill_decrypt(text: str, a: int, b: int, c: int, d: int) -> str:
    if len(_clean(text)) % 2 == 1:
        raise InvalidInput("Un texte chiffre par Hill 2x2 a une longueur paire.")
    matrix = _key_matrix(a, b, c, d)
    return _apply(text, _inverse_matrix(matrix))
