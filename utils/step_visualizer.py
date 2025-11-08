# Fichier: utils/step_visualizer.py
import string
import math
# Assurez-vous que tous les imports sont présents
from . import playfair, rail_fence, caesar, vigenere
from . import des_simulator, aes_simulator  # Assurez-vous qu'ils sont aussi là


# --- SIMULATE CAESAR (INCHANGÉ) ---
def simulate_caesar_encrypt(text: str, shift: int) -> dict:
    steps = []
    result = ""
    steps.append({
        "step": 0,
        "description": f"Initialisation avec le texte '{text}' et un décalage de {shift}."
    })
    for index, char in enumerate(text):
        step_description = f"Traitement du caractère '{char}' à l'index {index}."
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            original_ord = ord(char)
            base_ord = ord(base)
            new_ord = (original_ord - base_ord + shift) % 26 + base_ord
            new_char = chr(new_ord)
            step_description += f"\n  - C'est une lettre. Base: '{base}'."
            step_description += f"\n  - Position originale: {original_ord - base_ord}."
            step_description += f"\n  - Calcul: ({(original_ord - base_ord)} + {shift}) % 26 = {(original_ord - base_ord + shift) % 26}."
            step_description += f"\n  - Nouveau caractère: ... = {new_ord} (soit '{new_char}')."
            result += new_char
        else:
            step_description += f"\n  - Caractère non-alphabétique, conservé tel quel."
            result += char
        steps.append({
            "step": index + 1,
            "description": step_description,
            "current_char": char,
            "output_char": result[-1],
            "intermediate_result": result
        })
    steps.append({
        "step": len(text) + 1,
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
    })
    return {"final_result": result, "steps": steps}


# --- SIMULATE VIGENERE (INCHANGÉ) ---
def simulate_vigenere_encrypt(text: str, key: str) -> dict:
    steps = []
    result = ""
    key_upper = key.upper()
    key_len = len(key_upper)
    key_index = 0
    steps.append({
        "step": 0,
        "description": f"Initialisation. Texte: '{text}', Clé: '{key}'. Clé normalisée: '{key_upper}'."
    })
    for index, char in enumerate(text):
        description = f"Traitement du caractère '{char}' (index {index})."
        current_key_char = "N/A"
        output_char = char
        if 'a' <= char <= 'z':
            base = ord('a')
            current_key_char = key_upper[key_index % key_len]
            key_shift = ord(current_key_char) - ord('A')
            new_ord = (ord(char) - base + key_shift) % 26 + base
            output_char = chr(new_ord)
            description += f"\n  - Caractère (minuscule)."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}', décalage={key_shift})."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."
            key_index += 1
        elif 'A' <= char <= 'Z':
            base = ord('A')
            current_key_char = key_upper[key_index % key_len]
            key_shift = ord(current_key_char) - ord('A')
            new_ord = (ord(char) - base + key_shift) % 26 + base
            output_char = chr(new_ord)
            description += f"\n  - Caractère (majuscule)."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}', décalage={key_shift})."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."
            key_index += 1
        else:
            description += f"\n  - Caractère non-alphabétique. Conservé tel quel."
        result += output_char
        steps.append({
            "step": index + 1,
            "description": description,
            "current_char": char,
            "key_char_used": current_key_char,
            "output_char": output_char,
            "intermediate_result": result
        })
    steps.append({
        "step": len(text) + 1,
        "description": f"Fin du processus. Résultat final: '{result}'.",
        "final_result": result
    })
    return {"final_result": result, "steps": steps}


# --- SIMULATE PLAYFAIR (CORRIGÉ) ---
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

        # --- CORRECTION ---
        # Appelle la nouvelle fonction qui renvoie (formatted_word, description)
        formatted_word, desc = playfair.format_word_to_digrams_trace(original_word)
        desc_finale = f"Traitement du mot {i + 1} ('{original_word}').\n" + desc
        # --- FIN CORRECTION ---

        digrams = [formatted_word[k:k + 2] for k in range(0, len(formatted_word), 2)]
        all_digrams.extend(digrams)
        total_formatted_message += formatted_word

        steps.append({
            "step": step_counter,
            "phase": "Message Formatting",
            "description": desc_finale,  # Utilise la description retournée
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

            desc = f"Traitement du digramme '{pair}'.\n  - '{char1}' est en ({r1}, {c1}).\n  - '{char2}' est en ({r2}, {c2})."

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

    return {"final_result": result, "steps": steps, "matrix": matrix, "input_text": text}


# Fichier: utils/step_visualizer.py (Extrait pour Rail Fence)

# ... (autres imports et fonctions) ...

def simulate_rail_fence_encrypt(text: str, depth: int) -> dict:
    """
    Génère une trace étape par étape du chiffrement Rail Fence (Grille).
    """
    steps = []

    if depth <= 1:
        steps.append({"step": 0, "phase": "Erreur", "description": "La profondeur (depth) doit être > 1."})
        return {"final_result": text, "steps": steps}

    # --- PHASE 1: Calculs et Padding ---
    num_cols = math.ceil(len(text) / depth)
    padding_len = (num_cols * depth) - len(text)
    padded_text = text + "X" * padding_len

    steps.append({
        "step": 0,
        "phase": "Initialisation",
        "description": (
            f"Calcul des dimensions.\n"
            f"  - Texte: '{text}', Profondeur (Clé): {depth}\n"
            f"  - Nb. Colonnes: {num_cols} (car ceil({len(text)} / {depth}) = {num_cols})\n"
            f"  - Padding nécessaire: {padding_len} 'X'\n"
            f"  - Texte à chiffrer: '{padded_text}'"
        ),
        "input_text": padded_text,
        "output_text": ""
    })

    # --- PHASE 2: Remplissage (Écriture Verticale) ---
    matrix = [["" for _ in range(num_cols)] for _ in range(depth)]
    k = 0
    step_counter = 1

    # Initialise la matrice pour l'affichage
    steps.append({
        "step": step_counter,
        "phase": "Écriture",
        "description": "Démarrage de l'écriture verticale (colonne par colonne).",
        "matrix": [row[:] for row in matrix],
        "current_pos": [-1, -1]
    })
    step_counter += 1

    for c in range(num_cols):
        for r in range(depth):
            if k < len(padded_text):
                char = padded_text[k]
                matrix[r][c] = char
                steps.append({
                    "step": step_counter,
                    "phase": "Écriture",
                    "description": f"Écriture: '{char}' placée en colonne {c}, ligne {r}.",
                    "matrix": [row[:] for row in matrix],  # Copie de l'état
                    "current_char": char,
                    "current_pos": [r, c]
                })
                k += 1
                step_counter += 1

    # --- PHASE 3: Lecture (Lecture Horizontale) ---
    cipher_text = ""
    steps.append({
        "step": step_counter,
        "phase": "Lecture",
        "description": "Démarrage de la lecture horizontale (ligne par ligne).",
        "matrix": matrix,
        "current_pos": [-1, -1],
        "intermediate_result": ""
    })
    step_counter += 1

    for r in range(depth):
        for c in range(num_cols):
            char = matrix[r][c]
            cipher_text += char
            steps.append({
                "step": step_counter,
                "phase": "Lecture",
                "description": f"Lecture: '{char}' lue depuis ligne {r}, colonne {c}.",
                "matrix": matrix,
                "current_char": char,
                "current_pos": [r, c],
                "intermediate_result": cipher_text
            })
            step_counter += 1

    # Étape finale
    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Résultat final: '{cipher_text}'.",
        "final_result": cipher_text,
        "matrix": matrix
    })

    return {"final_result": cipher_text, "steps": steps, "matrix": matrix, "input_text": padded_text}