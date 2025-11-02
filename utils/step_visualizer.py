import string

from . import playfair
def simulate_caesar_encrypt(text: str, shift: int) -> dict:
    """
    Génère une trace étape par étape du chiffrement de César.
    Retourne le résultat final et la liste des étapes.
    """
    steps = []  # Une liste pour stocker la description de chaque étape
    result = ""

    # Étape 0 : Initialisation
    steps.append({
        "step": 0,
        "description": f"Initialisation avec le texte '{text}' et un décalage de {shift}."
    })

    for index, char in enumerate(text):
        step_description = f"Traitement du caractère '{char}' à l'index {index}."

        if char.isalpha():
            base = 'A' if char.isupper() else 'a'

            # Calcul de la nouvelle position
            original_ord = ord(char)
            base_ord = ord(base)

            # Formule: (position_lettre + décalage) % 26
            new_ord = (original_ord - base_ord + shift) % 26 + base_ord
            new_char = chr(new_ord)

            step_description += f"\n  - C'est une lettre. Base: '{base}' (ASCII {base_ord})."
            step_description += f"\n  - Position originale: {original_ord - base_ord} (car '{char}' - '{base}')."
            step_description += f"\n  - Calcul: ({(original_ord - base_ord)} + {shift}) % 26 = {(original_ord - base_ord + shift) % 26}."
            step_description += f"\n  - Nouveau caractère: {(original_ord - base_ord + shift) % 26} + {base_ord} = {new_ord} (soit '{new_char}')."

            result += new_char
        else:
            # Gérer les non-alphabétiques (espaces, ponctuation)
            step_description += f"\n  - Ce n'est pas une lettre, le caractère est conservé tel quel."
            result += char

        steps.append({
            "step": index + 1,
            "description": step_description,
            "current_char": char,
            "output_char": result[-1],
            "intermediate_result": result
        })

    # Étape finale
    steps.append({
        "step": len(text) + 1,
        "description": f"Fin du processus. Résultat final: '{result}'."
    })

    return {"final_result": result, "steps": steps}



def simulate_vigenere_encrypt(text: str, key: str) -> dict:
    """
    Génère une trace étape par étape du chiffrement de Vigenère.
    """
    steps = []
    result = ""
    key_upper = key.upper()
    key_len = len(key_upper)
    key_index = 0

    # Étape 0 : Initialisation
    steps.append({
        "step": 0,
        "description": f"Initialisation. Texte: '{text}', Clé: '{key}'. Clé normalisée pour les décalages: '{key_upper}'."
    })

    for index, char in enumerate(text):
        description = f"Traitement du caractère '{char}' (index {index})."
        current_key_char = "N/A"
        key_shift_info = "N/A"
        output_char = char  # Par défaut, le caractère est conservé

        if 'a' <= char <= 'z':
            base = ord('a')
            base_char = 'a'
            current_key_char = key_upper[key_index % key_len]
            key_shift = ord(current_key_char) - ord('A')

            new_ord = (ord(char) - base + key_shift) % 26 + base
            output_char = chr(new_ord)

            description += f"\n  - Caractère (minuscule). Base: '{base_char}'."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}')."
            description += f"\n  - Décalage: {key_shift} (car '{current_key_char}' - 'A')."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."

            key_index += 1  # L'index de la clé avance

        elif 'A' <= char <= 'Z':
            base = ord('A')
            base_char = 'A'
            current_key_char = key_upper[key_index % key_len]
            key_shift = ord(current_key_char) - ord('A')

            new_ord = (ord(char) - base + key_shift) % 26 + base
            output_char = chr(new_ord)

            description += f"\n  - Caractère (majuscule). Base: '{base_char}'."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}')."
            description += f"\n  - Décalage: {key_shift} (car '{current_key_char}' - 'A')."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."

            key_index += 1  # L'index de la clé avance

        else:
            description += f"\n  - Caractère non-alphabétique. Conservé tel quel."
            description += f"\n  - L'index de la clé ({key_index}) n'est pas incrémenté."

        result += output_char
        steps.append({
            "step": index + 1,
            "description": description,
            "current_char": char,
            "key_char_used": current_key_char,
            "output_char": output_char,
            "intermediate_result": result
        })

    # Étape finale
    steps.append({
        "step": len(text) + 1,
        "description": f"Fin du processus. Résultat final: '{result}'."
    })

    return {"final_result": result, "steps": steps}


def simulate_playfair_encrypt(text: str, key: str) -> dict:
    """
    Génère une trace étape par étape du chiffrement de Playfair.
    """
    steps = []

    # --- PHASE 1: GÉNÉRATION DE LA MATRICE ---
    key_upper = key.upper().replace("J", "I")
    matrix_str = ""
    seen = set()

    steps.append({
        "step": 1,
        "phase": "Matrix Generation",
        "description": f"Démarrage de la génération de la matrice 5x5 avec la clé '{key}'.\nClé normalisée (J->I, majuscules): '{key_upper}'."
    })

    # Ajouter les caractères de la clé
    for char in key_upper:
        if char not in seen and 'A' <= char <= 'Z':
            matrix_str += char
            seen.add(char)

    # Ajouter le reste de l'alphabet (sans 'J')
    alphabet = string.ascii_uppercase.replace("J", "")
    for char in alphabet:
        if char not in seen:
            matrix_str += char
            seen.add(char)

    # Convertir la chaîne en matrice 5x5
    matrix = [list(matrix_str[i:i + 5]) for i in range(0, 25, 5)]

    steps.append({
        "step": 2,
        "phase": "Matrix Generation",
        "description": f"Matrice 5x5 finale générée.\nChaîne de matrice: {matrix_str}",
        "matrix": matrix
    })

    # --- PHASE 2: FORMATAGE DU MESSAGE ---
    text_upper = text.upper().replace("J", "I")
    steps.append({
        "step": 3,
        "phase": "Message Formatting",
        "description": f"Formatage du message '{text}'.\nMessage normalisé (J->I, majuscules): '{text_upper}'."
    })

    # Gérer les lettres doubles (ex: "HELLO" -> "HELXLO")
    formatted = ""
    i = 0
    temp_text = text_upper
    while i < len(temp_text):
        formatted += temp_text[i]
        if i + 1 < len(temp_text) and temp_text[i] == temp_text[i + 1]:
            formatted += "X"
            temp_text = temp_text[:i + 1] + "X" + temp_text[i + 1:]  # Insérer un X
        elif i + 1 < len(temp_text):
            formatted += temp_text[i + 1]
            i += 1
        i += 1

    # Ajouter un 'X' si la longueur est impaire
    if len(formatted) % 2 != 0:
        formatted += "X"
        padding_step_desc = f"Message après gestion des doublons: '{formatted[:-1]}'.\nLongueur impaire. Ajout d'un 'X' de remplissage."
    else:
        padding_step_desc = f"Message après gestion des doublons: '{formatted}'.\nLongueur paire. Pas de remplissage nécessaire."

    digrams = [formatted[i:i + 2] for i in range(0, len(formatted), 2)]

    steps.append({
        "step": 4,
        "phase": "Message Formatting",
        "description": padding_step_desc,
        "formatted_message": formatted,
        "digrams": digrams
    })

    # --- PHASE 3: CHIFFREMENT DES DIGRAMMES ---
    steps.append({
        "step": 5,
        "phase": "Encryption",
        "description": f"Démarrage du chiffrement de {len(digrams)} digrammes..."
    })

    result = ""
    step_counter = 6

    for pair in digrams:
        char1, char2 = pair[0], pair[1]
        r1, c1 = playfair.find_position(matrix, char1)
        r2, c2 = playfair.find_position(matrix, char2)

        description = f"Traitement du digramme '{pair}'.\n  - '{char1}' est en ({r1}, {c1}).\n  - '{char2}' est en ({r2}, {c2})."

        new_char1, new_char2 = '', ''

        if r1 == r2:  # Règle 1: Même ligne
            c1_new = (c1 + 1) % 5
            c2_new = (c2 + 1) % 5
            new_char1 = matrix[r1][c1_new]
            new_char2 = matrix[r2][c2_new]
            description += f"\n  - RÈGLE: Même ligne. Décalage à droite (circulaire)."
            description += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({r1},{c1_new})."
            description += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({r2},{c2_new})."

        elif c1 == c2:  # Règle 2: Même colonne
            r1_new = (r1 + 1) % 5
            r2_new = (r2 + 1) % 5
            new_char1 = matrix[r1_new][c1]
            new_char2 = matrix[r2_new][c2]
            description += f"\n  - RÈGLE: Même colonne. Décalage en bas (circulaire)."
            description += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({r1_new},{c1})."
            description += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({r2_new},{c2})."

        else:  # Règle 3: Rectangle
            new_char1 = matrix[r1][c2]
            new_char2 = matrix[r2][c1]
            description += f"\n  - RÈGLE: Rectangle. Échange des colonnes."
            description += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({r1},{c2})."
            description += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({r2},{c1})."

        new_pair = new_char1 + new_char2
        result += new_pair

        steps.append({
            "step": step_counter,
            "phase": "Encryption",
            "description": description,
            "input_digram": pair,
            "output_digram": new_pair,
            "intermediate_result": result
        })
        step_counter += 1

    # Étape finale
    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
    })

    return {"final_result": result, "steps": steps}

