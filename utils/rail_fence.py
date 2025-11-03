# Fichier: utils/rail_fence.py
import math


def rail_fence_encrypt(text: str, depth: int) -> str:
    """
    Chiffre un texte en utilisant le Chiffre de Grille (Rail Fence).
    Écrit verticalement, lit horizontalement.
    """
    if depth <= 1:
        return text

    # 1. Calculer les dimensions et le padding
    num_cols = math.ceil(len(text) / depth)
    padding_len = (num_cols * depth) - len(text)
    padded_text = text + "X" * padding_len

    # 2. Créer la matrice
    matrix = [["" for _ in range(num_cols)] for _ in range(depth)]

    # 3. Remplir la matrice (verticalement, colonne par colonne)
    k = 0
    for c in range(num_cols):
        for r in range(depth):
            if k < len(padded_text):
                matrix[r][c] = padded_text[k]
                k += 1

    # 4. Lire la matrice (horizontalement, ligne par ligne)
    cipher_text = ""
    for r in range(depth):
        for c in range(num_cols):
            cipher_text += matrix[r][c]

    return cipher_text


def rail_fence_decrypt(cipher_text: str, depth: int) -> str:
    """
    Déchiffre un texte du Chiffre de Grille (Rail Fence).
    Écrit horizontalement, lit verticalement.
    """
    if depth <= 1:
        return cipher_text

    n = len(cipher_text)

    # 1. Calculer les dimensions
    if n % depth != 0:
        # Le texte chiffré doit être un multiple de la profondeur
        return "Erreur: Longueur du chiffré invalide pour cette profondeur."

    num_cols = int(n / depth)

    # 2. Créer la matrice
    matrix = [["" for _ in range(num_cols)] for _ in range(depth)]

    # 3. Remplir la matrice (horizontalement, ligne par ligne)
    k = 0
    for r in range(depth):
        for c in range(num_cols):
            if k < n:
                matrix[r][c] = cipher_text[k]
                k += 1

    # 4. Lire la matrice (verticalement, colonne par colonne)
    plain_text = ""
    for c in range(num_cols):
        for r in range(depth):
            plain_text += matrix[r][c]

    # Le résultat peut contenir des 'X' de padding, c'est normal
    return plain_text