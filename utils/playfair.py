import string


def generate_playfair_matrix(key: str) -> list[list[str]]:
    """Génère la matrice Playfair 5x5."""
    key = key.upper().replace("J", "I") + string.ascii_uppercase.replace("J", "")
    matrix = []
    seen = set()
    for char in key:
        if char not in seen:
            matrix.append(char)
            seen.add(char)

    # Convertit la liste plate en matrice 5x5
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def format_message(text: str) -> list[str]:
    """Formate le message en digrammes pour Playfair."""
    text = text.upper().replace("J", "I").replace(" ", "")

    # 1. Gérer les lettres doubles (ex: "HELLO" -> "HELXLO")
    formatted = ""
    i = 0
    while i < len(text):
        formatted += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            formatted += "X"
        elif i + 1 < len(text):
            formatted += text[i + 1]
            i += 1
        i += 1

    # 2. Ajouter un 'X' si la longueur est impaire
    if len(formatted) % 2 != 0:
        formatted += "X"

    # 3. Diviser en digrammes
    return [formatted[i:i + 2] for i in range(0, len(formatted), 2)]


def find_position(matrix: list[list[str]], char: str) -> tuple[int, int]:
    """Trouve la position (ligne, colonne) d'un caractère dans la matrice."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return -1, -1  # Ne devrait pas arriver


def playfair_encrypt(plain_text: str, key: str) -> str:
    """Chiffre un texte avec Playfair."""
    matrix = generate_playfair_matrix(key)
    digrams = format_message(plain_text)
    cipher_text = ""

    for pair in digrams:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])

        if r1 == r2:  # Même ligne
            cipher_text += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # Même colonne
            cipher_text += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:  # Rectangle
            cipher_text += matrix[r1][c2] + matrix[r2][c1]

    return cipher_text


def playfair_decrypt(cipher_text: str, key: str) -> str:
    """Déchiffre un texte avec Playfair."""
    matrix = generate_playfair_matrix(key)
    # Le texte chiffré est déjà en digrammes
    digrams = [cipher_text[i:i + 2] for i in range(0, len(cipher_text), 2)]
    plain_text = ""

    for pair in digrams:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])

        if r1 == r2:  # Même ligne
            plain_text += matrix[r1][(c1 - 1 + 5) % 5] + matrix[r2][(c2 - 1 + 5) % 5]
        elif c1 == c2:  # Même colonne
            plain_text += matrix[(r1 - 1 + 5) % 5][c1] + matrix[(r2 - 1 + 5) % 5][c2]
        else:  # Rectangle
            plain_text += matrix[r1][c2] + matrix[r2][c1]

    # Note: Le texte déchiffré peut contenir des 'X' de remplissage
    return plain_text