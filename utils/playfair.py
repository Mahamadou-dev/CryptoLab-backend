import string


def generate_playfair_matrix(key: str) -> list[list[str]]:
    """Génère la matrice Playfair 5x5."""
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
    return -1, -1  # Caractère non trouvé (ne devrait pas arriver si J=I)


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

        if i + 1 >= len(word):
            break  # Fin du mot

        char2 = word[i + 1]
        if not char2.isalpha():  # Gère "BAL L ON"
            i += 1
            continue  # Saute le caractère non-alpha, le prochain tour le gérera

        if char1 == char2:
            formatted += "X"
            i += 1  # Avance d'un seul cran (pour réutiliser le 2e 'L')
        else:
            formatted += char2
            i += 2  # Avance de deux crans

    # 2. Ajouter 'X' si la longueur est impaire (selon votre nouvelle règle)
    if len(formatted) % 2 != 0:
        formatted += "X"

    # 3. Diviser en digrammes
    return [formatted[i:i + 2] for i in range(0, len(formatted), 2)]


def process_playfair(text: str, key: str, mode: str) -> str:
    """Fonction principale pour chiffrer ou déchiffrer avec les nouvelles règles."""
    matrix = generate_playfair_matrix(key)
    words = text.split(' ')  # Sépare par espaces
    result_text = ""

    for word_index, word in enumerate(words):
        if not word:  # Gère les espaces multiples
            if word_index < len(words) - 1:  # N'ajoute pas d'espace final
                result_text += " "
            continue

        digrams = format_word_to_digrams(word)
        result_word = ""

        for pair in digrams:
            r1, c1 = find_position(matrix, pair[0])
            r2, c2 = find_position(matrix, pair[1])

            # Gère les caractères non-matrice (chiffres, ponctuation, ou -1)
            if r1 < 0 or r2 < 0:
                result_word += pair
                continue

            if r1 == r2:  # Même ligne
                shift = 1 if mode == 'encrypt' else -1
                result_word += matrix[r1][(c1 + shift) % 5] + matrix[r2][(c2 + shift) % 5]
            elif c1 == c2:  # Même colonne
                shift = 1 if mode == 'encrypt' else -1
                result_word += matrix[(r1 + shift) % 5][c1] + matrix[(r2 + shift) % 5][c2]
            else:  # Rectangle
                result_word += matrix[r1][c2] + matrix[r2][c1]

        result_text += result_word
        if word_index < len(words) - 1:  # Ajoute l'espace
            result_text += " "

    return result_text


def playfair_encrypt(plain_text: str, key: str) -> str:
    """Chiffre un texte avec Playfair en gardant les espaces."""
    return process_playfair(plain_text, key, 'encrypt')


def playfair_decrypt(cipher_text: str, key: str) -> str:
    """Déchiffre un texte avec Playfair en gardant les espaces."""
    # Note: Le déchiffrement ne retirera pas les 'X' de padding.
    return process_playfair(cipher_text, key, 'decrypt')
