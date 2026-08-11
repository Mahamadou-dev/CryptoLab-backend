"""
Chiffre du Rail Fence (zigzag) — le vrai.

ATTENTION HISTORIQUE : l'ancienne version de ce fichier n'implementait pas un
Rail Fence. Elle remplissait une grille verticalement et la lisait
horizontalement, ce qui est une *transposition par colonnes*. Cet algorithme a
ete deplace dans utils/columnar.py, ou il porte desormais son vrai nom.

Le Rail Fence ecrit le texte en zigzag sur `rails` lignes, puis lit les lignes
de haut en bas.

    Texte "WEAREDISCOVERED", 3 rails :

        W . . . E . . . C . . . R . .
        . E . R . D . S . O . E . E .
        . . A . . . I . . . V . . . D

    Lecture ligne par ligne -> "WECR" + "ERDSOEE" + "AIVD" = "WECRERDSOEEAIVD"

La transformation ne porte que sur des positions : tous les caracteres, espaces
et ponctuation compris, sont conserves et l'aller-retour est exact.
"""



def _rail_pattern(length: int, rails: int) -> list[int]:
    """
    Retourne, pour chaque position du texte, l'indice du rail qui l'accueille.

    Le motif descend de 0 a rails-1, puis remonte, indefiniment.
    """
    pattern = []
    rail = 0
    direction = 1
    for _ in range(length):
        pattern.append(rail)
        # On inverse le sens en haut et en bas de la cloture.
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return pattern


def rail_fence_encrypt(text: str, rails: int) -> str:
    """
    Chiffre un texte en zigzag sur `rails` lignes.

    Args:
        text: le texte a chiffrer (tous les caracteres sont conserves).
        rails: le nombre de rails (>= 2 ; 1 ou moins renvoie le texte intact).
    """
    if rails <= 1 or len(text) <= 1:
        return text

    rows: list[list[str]] = [[] for _ in range(rails)]
    for char, rail in zip(text, _rail_pattern(len(text), rails), strict=True):
        rows[rail].append(char)

    return "".join("".join(row) for row in rows)


def rail_fence_decrypt(cipher_text: str, rails: int) -> str:
    """
    Dechiffre un texte Rail Fence. Inverse exact de `rail_fence_encrypt`.
    """
    if rails <= 1 or len(cipher_text) <= 1:
        return cipher_text

    pattern = _rail_pattern(len(cipher_text), rails)

    # Combien de caracteres chaque rail a-t-il recu ?
    counts = [pattern.count(r) for r in range(rails)]

    # On redecoupe le chiffre en tranches, une par rail.
    slices: list[list[str]] = []
    position = 0
    for count in counts:
        slices.append(list(cipher_text[position:position + count]))
        position += count

    # Puis on relit le zigzag en piochant dans la tranche du rail courant.
    cursors = [0] * rails
    plain = []
    for rail in pattern:
        plain.append(slices[rail][cursors[rail]])
        cursors[rail] += 1

    return "".join(plain)


def rail_fence_grid(text: str, rails: int) -> list[list[str]]:
    """
    Construit la grille du zigzag pour l'affichage pedagogique.

    Les cases vides sont representees par une chaine vide, ce qui permet au
    frontend de dessiner la cloture telle qu'elle est ecrite dans les manuels.
    """
    if rails <= 1:
        return [list(text)]

    grid = [["" for _ in range(len(text))] for _ in range(rails)]
    for column, (char, rail) in enumerate(zip(text, _rail_pattern(len(text), rails), strict=True)):
        grid[rail][column] = char
    return grid
