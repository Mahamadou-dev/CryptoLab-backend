# Fichier: utils/rail_fence.py
import math


def rail_fence_encrypt(text: str, depth: int) -> str:
    """
    Chiffre un texte en utilisant le Chiffre de Grille (Rail Fence).
    Supprime les espaces avant de chiffrer.
    """
    if depth <= 1:
        return text

    # --- NOUVEAU : Suppression des espaces ---
    text = text.replace(" ", "")
    # -----------------------------------------

    # 1. Calculer les dimensions et le padding
    num_cols = math.ceil(len(text) / depth)
    total_cells = num_cols * depth
    padding_len = total_cells - len(text)
    padded_text = text + "X" * padding_len

    # ... (le reste de la fonction est inchangé) ...
    # 2. Créer la matrice
    matrix = [['' for _ in range(num_cols)] for _ in range(depth)]
    # 3. Remplir la matrice VERTICALEMENT
    k = 0
    for c in range(num_cols):
        for r in range(depth):
            if k < len(padded_text):
                matrix[r][c] = padded_text[k]
                k += 1
    # 4. Lire la matrice HORIZONTALEMENT
    cipher_text = ""
    for r in range(depth):
        for c in range(num_cols):
            cipher_text += matrix[r][c]

    return cipher_text

def rail_fence_decrypt(cipher_text: str, depth: int) -> str:
    """
    Déchiffre un texte du Chiffre de Grille (Rail Fence).
    Écrit horizontalement (ligne par ligne), lit verticalement (colonne par colonne).
    """
    if depth <= 1:
        return cipher_text

    n = len(cipher_text)

    # 1. Vérification et calcul des dimensions
    if n % depth != 0:
        # Si la longueur n'est pas un multiple de la profondeur, ce n'est pas un chiffré valide
        # (ou il manque des caractères). On tente quand même de continuer.
        pass

    num_cols = math.ceil(n / depth)
    # On s'assure que la matrice a la bonne taille pour contenir tout le texte
    total_cells = num_cols * depth
    if n < total_cells:
        # On ajoute du padding si nécessaire pour remplir la grille (cas rare si l'entrée est valide)
        cipher_text += "X" * (total_cells - n)

    # 2. Créer la matrice vide
    matrix = [['' for _ in range(num_cols)] for _ in range(depth)]

    # 3. Remplir la matrice HORIZONTALEMENT (ligne par ligne) avec le texte chiffré
    k = 0
    for r in range(depth):
        for c in range(num_cols):
            if k < len(cipher_text):
                matrix[r][c] = cipher_text[k]
                k += 1

    # 4. Lire la matrice VERTICALEMENT (colonne par colonne) pour retrouver le clair
    plain_text = ""
    for c in range(num_cols):
        for r in range(depth):
            plain_text += matrix[r][c]

    return plain_text