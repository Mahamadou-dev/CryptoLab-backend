"""
Fonctions mathématiques pour AES, opérant dans le corps de Galois GF(2^8)
avec le polynôme irréductible x^8 + x^4 + x^3 + x + 1 (0x11B).
"""


def gadd(a: int, b: int) -> int:
    """
    Addition dans GF(2^8). C'est simplement un XOR.
    """
    return a ^ b


def gmul_by_02(b: int) -> int:
    """
    Multiplication par 2 (l'opération 'xtime').
    Équivaut à un décalage à gauche, suivi d'un XOR avec 0x11B si
    le bit de poids fort était 1 (overflow).
    """
    if b < 0x80:
        # Pas d'overflow, simple décalage
        res = (b << 1)
    else:
        # Overflow
        res = (b << 1) ^ 0x11B
    return res & 0xFF  # Assure qu'on reste sur 8 bits


def gmul_by_03(b: int) -> int:
    """
    Multiplication par 3.
    gmul(b, 3) = gmul(b, 2) ^ gmul(b, 1)
    """
    return gadd(gmul_by_02(b), b)


def gmul(a: int, b: int) -> int:
    """
    Multiplication générale dans GF(2^8) (Peasant's Algorithm).
    """
    p = 0
    for _ in range(8):
        if (b & 1) == 1:
            p = gadd(p, a)  # p ^= a

        # Vérifier si 'a' va déborder
        high_bit_set = (a & 0x80)
        a = (a << 1) & 0xFF  # Décalage à gauche (et garde sur 8 bits)

        if high_bit_set:
            a = gadd(a, 0x1B)  # a ^= 0x1B (version 8 bits de 0x11B)

        b = b >> 1  # Décalage à droite
    return p


# --- MixColumns Helpers ---
# La matrice fixe pour MixColumns
MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]


def mix_single_column(column: list) -> list:
    """
    Applique l'opération MixColumns à une seule colonne (liste de 4 bytes).
    """
    new_col = [0] * 4
    for r in range(4):
        # C'est une multiplication de matrice : new_col[r] = sum(Matrix[r][c] * column[c])
        new_val = 0
        new_val = gadd(new_val, gmul(MIX_COLUMNS_MATRIX[r][0], column[0]))
        new_val = gadd(new_val, gmul(MIX_COLUMNS_MATRIX[r][1], column[1]))
        new_val = gadd(new_val, gmul(MIX_COLUMNS_MATRIX[r][2], column[2]))
        new_val = gadd(new_val, gmul(MIX_COLUMNS_MATRIX[r][3], column[3]))
        new_col[r] = new_val
    return new_col