import string

from typing import List


def generate_playfair_matrix(key: str) -> list[list[str]]:
    """Génère la matrice Playfair 5x5."""
    # Combine I et J
    key = key.upper().replace("J", "I") + string.ascii_uppercase.replace("J", "")
    matrix = []
    seen = set()
    for char in key:
        if char.isalpha() and char not in seen:
            matrix.append(char)
            seen.add(char)

    # Convertit la liste plate en matrice 5x5
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix: list[list[str]], char: str) -> tuple[int, int]:
    """Trouve la position (ligne, colonne) d'un caractère dans la matrice."""
    if not char.isalpha():
        return -1, -1
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return -1, -1  # Ne devrait pas arriver pour les lettres valides


def format_word_to_digrams(word: str) -> list[str]:
    """Formate un seul mot en digrammes, gère les doublons et le padding."""
    word = word.upper().replace("J", "I")

    # 1. Gérer les lettres doubles (CORRIGÉ)
    #    Ex: "HELLO" -> "HE" + "L" + "X" + "L" + "O"
    i = 0
    formatted = ""
    while i < len(word):
        char1 = word[i]

        if not char1.isalpha():  # Ignore les non-lettres
            i += 1
            continue

        formatted += char1

        # Trouver le prochain caractère alphabétique
        j = i + 1
        while j < len(word) and not word[j].isalpha():
            j += 1

        if j >= len(word):  # Fin du mot
            break

        char2 = word[j]

        if char1 == char2:
            formatted += "X"  # Insère 'X'
            i = j  # Recommence à partir de la lettre doublon
        else:
            formatted += char2
            i = j + 1  # Passe à la lettre suivante après la paire

    # 2. Ajouter un 'X' si la longueur est impaire
    if len(formatted) % 2 != 0:
        formatted += "X"

    # 3. Diviser en digrammes
    return [formatted[i:i + 2] for i in range(0, len(formatted), 2)]


def playfair_encrypt(plain_text: str, key: str) -> str:
    """Chiffre un texte avec Playfair, en conservant les espaces."""
    matrix = generate_playfair_matrix(key)
    cipher_text = ""
    words = plain_text.split(' ')

    for i, word in enumerate(words):
        if not word:  # Gère les espaces multiples
            if i < len(words) - 1:  # N'ajoute pas d'espace final
                cipher_text += " "
            continue

        digrams = format_word_to_digrams(word)

        for pair in digrams:
            r1, c1 = find_position(matrix, pair[0])
            r2, c2 = find_position(matrix, pair[1])

            if r1 < 0 or r2 < 0:  # Si un caractère n'est pas dans la grille (non-alpha)
                cipher_text += pair
                continue

            if r1 == r2:  # Même ligne
                cipher_text += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
            elif c1 == c2:  # Même colonne
                cipher_text += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
            else:  # Rectangle
                cipher_text += matrix[r1][c2] + matrix[r2][c1]

        if i < len(words) - 1:
            cipher_text += " "

    return cipher_text


def playfair_decrypt(cipher_text: str, key: str) -> str:
    """Déchiffre un texte avec Playfair, en conservant les espaces."""
    matrix = generate_playfair_matrix(key)
    plain_text = ""
    words = cipher_text.split(' ')

    for i, word in enumerate(words):
        if not word:
            if i < len(words) - 1:
                plain_text += " "
            continue

        # Ne PAS reformater le texte chiffré. Juste le découper.
        digrams = [word[j:j + 2] for j in range(0, len(word), 2)]

        for pair in digrams:
            if len(pair) != 2:  # Gère le cas d'un mot impair (ne devrait pas arriver si chiffré)
                plain_text += pair
                continue

            r1, c1 = find_position(matrix, pair[0])
            r2, c2 = find_position(matrix, pair[1])

            if r1 < 0 or r2 < 0:
                plain_text += pair
                continue

            if r1 == r2:  # Même ligne
                plain_text += matrix[r1][(c1 - 1 + 5) % 5] + matrix[r2][(c2 - 1 + 5) % 5]
            elif c1 == c2:  # Même colonne
                plain_text += matrix[(r1 - 1 + 5) % 5][c1] + matrix[(r2 - 1 + 5) % 5][c2]
            else:  # Rectangle
                plain_text += matrix[r1][c2] + matrix[r2][c1]

        if i < len(words) - 1:
            plain_text += " "

    # Note: Le texte déchiffré peut contenir des 'X' de remplissage
    return plain_text

