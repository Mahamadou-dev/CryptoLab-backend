"""
Transposition par colonnes (columnar transposition).

C'est l'algorithme que l'ancien utils/rail_fence.py implementait reellement,
sous un nom qui n'etait pas le sien. Il a droit ici a sa propre page.

Principe : le texte est ecrit ligne par ligne dans une grille dont la largeur
est la longueur de la cle. Les colonnes sont ensuite lues dans l'ordre
alphabetique des lettres de la cle.

    Cle "ZEBRAS" -> ordre de lecture des colonnes : 4 2 1 3 5 0
    (la colonne du A vient en premier, puis celle du B, du E, du R, du S, du Z)

    W E A R E D
    I S C O V E
    R E D F L E
    E A T O N C
    E

    Colonne "A" (index 4) lue en premier -> "EVLN", etc.

Variante *irreguliere* : les colonnes de fin peuvent etre plus courtes et on
n'ajoute AUCUN caractere de bourrage. L'aller-retour est donc exact, y compris
sur les espaces et la ponctuation — contrairement a l'ancienne version, qui
supprimait les espaces et laissait des "X" de padding dans le texte dechiffre.
"""



def key_order(key: str) -> list[int]:
    """
    Traduit une cle en ordre de lecture des colonnes.

    Retourne la liste des indices de colonnes, triee par la lettre de la cle.
    Les doublons sont departages par leur position (tri stable), comme le veut
    la convention classique.
    """
    normalised = [c.upper() for c in key if not c.isspace()]
    if not normalised:
        raise ValueError("La cle de transposition ne peut pas etre vide.")
    return sorted(range(len(normalised)), key=lambda i: (normalised[i], i))


def _column_lengths(text_length: int, width: int) -> list[int]:
    """Nombre de caracteres reellement presents dans chaque colonne."""
    full_rows, remainder = divmod(text_length, width)
    return [full_rows + (1 if col < remainder else 0) for col in range(width)]


def columnar_encrypt(text: str, key: str) -> str:
    """Chiffre un texte par transposition de colonnes."""
    order = key_order(key)
    width = len(order)
    if width <= 1 or not text:
        return text

    # Lecture des colonnes dans l'ordre impose par la cle.
    return "".join("".join(text[col::width]) for col in order)


def columnar_decrypt(cipher_text: str, key: str) -> str:
    """Dechiffre un texte transpose. Inverse exact de `columnar_encrypt`."""
    order = key_order(key)
    width = len(order)
    if width <= 1 or not cipher_text:
        return cipher_text

    lengths = _column_lengths(len(cipher_text), width)

    # On redistribue le chiffre dans les colonnes, dans l'ordre ou il a ete lu.
    columns: list[str] = [""] * width
    position = 0
    for col in order:
        columns[col] = cipher_text[position:position + lengths[col]]
        position += lengths[col]

    # Puis on relit la grille ligne par ligne.
    cursors = [0] * width
    plain = []
    for index in range(len(cipher_text)):
        col = index % width
        plain.append(columns[col][cursors[col]])
        cursors[col] += 1

    return "".join(plain)


def columnar_grid(text: str, key: str) -> tuple[list[list[str]], list[int]]:
    """
    Construit la grille et l'ordre des colonnes pour l'affichage pedagogique.

    Retourne (grille, ordre_de_lecture). Les cases manquantes de la derniere
    ligne sont des chaines vides — elles ne sont pas bourrees.
    """
    order = key_order(key)
    width = len(order)
    rows = -(-len(text) // width) if width else 0  # division arrondie au superieur

    grid = [["" for _ in range(width)] for _ in range(rows)]
    for index, char in enumerate(text):
        grid[index // width][index % width] = char

    return grid, order
