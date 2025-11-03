import string

from . import playfair  # Importe le NOUVEAU fichier playfair


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
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
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
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
    })

    return {"final_result": result, "steps": steps}


def simulate_playfair_encrypt(text: str, key: str) -> dict:
    """
    Génère une trace étape par étape du chiffrement de Playfair,
    en gérant les espaces et le padding par mot.
    """
    steps = []
    matrix = playfair.generate_playfair_matrix(key)

    # --- PHASE 1: GÉNÉRATION DE LA MATRICE ---
    steps.append({
        "step": 1,
        "phase": "Matrix Generation",
        "description": f"Génération de la matrice 5x5 avec la clé '{key}'.",
        "matrix": matrix
    })

    # --- PHASE 2: FORMATAGE DU MESSAGE (MOT PAR MOT) ---
    words = text.split(' ')
    all_digrams = []
    step_counter = 2

    steps.append({
        "step": step_counter,
        "phase": "Message Formatting",
        "description": f"Formatage du message mot par mot. (I=J, gestion des doublons, padding 'X' par mot)."
    })
    step_counter += 1

    total_formatted_message = ""
    for i, word in enumerate(words):
        if not word:
            total_formatted_message += " "
            steps.append({
                "step": step_counter,
                "phase": "Message Formatting",
                "description": f"Traitement du mot {i + 1} : Espace vide, conservé.",
                "intermediate_result": total_formatted_message
            })
            step_counter += 1
            continue

        original_word = word
        word = word.upper().replace("J", "I")

        # Gérer les doublons (Logique corrigée)
        j = 0
        formatted_word = ""
        while j < len(word):
            char1 = word[j]
            if not char1.isalpha():
                j += 1
                continue
            formatted_word += char1
            if j + 1 >= len(word):
                break
            char2 = word[j + 1]
            if not char2.isalpha():
                j += 1
                continue
            if char1 == char2:
                formatted_word += "X"
                j += 1
            else:
                formatted_word += char2
                j += 2

        desc = f"Traitement du mot {i + 1} ('{original_word}').\n  - Normalisé: '{word}'\n  - Gestion des doublons: '{formatted_word}'"

        # Gérer la fin de mot impaire
        if len(formatted_word) % 2 != 0:
            formatted_word += "X"
            desc += f"\n  - Longueur impaire, padding 'X': '{formatted_word}'"

        digrams = [formatted_word[k:k + 2] for k in range(0, len(formatted_word), 2)]
        all_digrams.extend(digrams)
        total_formatted_message += formatted_word

        steps.append({
            "step": step_counter,
            "phase": "Message Formatting",
            "description": desc,
            "digrams": digrams,
            "intermediate_result": total_formatted_message
        })
        step_counter += 1

        if i < len(words) - 1:
            total_formatted_message += " "

    # --- PHASE 3: CHIFFREMENT DES DIGRAMMES ---
    steps.append({
        "step": step_counter,
        "phase": "Encryption",
        "description": f"Démarrage du chiffrement de {len(all_digrams)} digrammes..."
    })
    step_counter += 1

    result = ""
    digram_index = 0

    # Re-parcourt le message formaté pour inclure les espaces
    words_formatted = total_formatted_message.split(' ')

    for word in words_formatted:
        if not word:
            result += " "
            continue

        digrams_in_word = [word[k:k + 2] for k in range(0, len(word), 2)]

        for pair in digrams_in_word:
            char1, char2 = pair[0], pair[1]
            r1, c1 = playfair.find_position(matrix, char1)
            r2, c2 = playfair.find_position(matrix, char2)

            desc = f"Traitement du digramme '{pair}' (Mot: '{word}').\n  - '{char1}' est en ({r1}, {c1}).\n  - '{char2}' est en ({r2}, {c2})."

            new_char1, new_char2 = '', ''

            if r1 < 0 or r2 < 0:  # Caractère non-alpha ou non trouvé
                new_char1, new_char2 = char1, char2
                desc += f"\n  - RÈGLE: Caractère(s) non-valide(s). Ignoré."
            elif r1 == r2:  # Règle 1: Même ligne
                new_char1 = matrix[r1][(c1 + 1) % 5]
                new_char2 = matrix[r2][(c2 + 1) % 5]
                desc += f"\n  - RÈGLE: Même ligne. Décalage à droite."
                desc += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({r1},{(c1 + 1) % 5})."
                desc += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({r2},{(c2 + 1) % 5})."
            elif c1 == c2:  # Règle 2: Même colonne
                new_char1 = matrix[(r1 + 1) % 5][c1]
                new_char2 = matrix[(r2 + 1) % 5][c2]
                desc += f"\n  - RÈGLE: Même colonne. Décalage en bas."
                desc += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({(r1 + 1) % 5},{c1})."
                desc += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({(r2 + 1) % 5},{c2})."
            else:  # Règle 3: Rectangle
                new_char1 = matrix[r1][c2]
                new_char2 = matrix[r2][c1]
                desc += f"\n  - RÈGLE: Rectangle. Échange des colonnes."
                desc += f"\n  - '{char1}' ({r1},{c1}) -> '{new_char1}' ({r1},{c2})."
                desc += f"\n  - '{char2}' ({r2},{c2}) -> '{new_char2}' ({r2},{c1})."

            new_pair = new_char1 + new_char2
            result += new_pair

            steps.append({
                "step": step_counter,
                "phase": "Encryption",
                "description": desc,
                "input_digram": pair,
                "output_digram": new_pair,
                "intermediate_result": result
            })
            step_counter += 1

        # Ajoute l'espace après le mot (sauf pour le dernier mot)
        if len(result) < len(total_formatted_message):
            if total_formatted_message[len(result)] == ' ':
                result += " "

    # Étape finale
    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
    })

    return {"final_result": result, "steps": steps}

