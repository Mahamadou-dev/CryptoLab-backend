# Fichier: utils/step_visualizer.py
# Assurez-vous que tous les imports sont présents
from . import columnar, playfair, rail_fence, sha1_tool, sha256_tool


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
            step_description += "\n  - Caractère non-alphabétique, conservé tel quel."
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
            description += "\n  - Caractère (minuscule)."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}', décalage={key_shift})."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."
            key_index += 1
        elif 'A' <= char <= 'Z':
            base = ord('A')
            current_key_char = key_upper[key_index % key_len]
            key_shift = ord(current_key_char) - ord('A')
            new_ord = (ord(char) - base + key_shift) % 26 + base
            output_char = chr(new_ord)
            description += "\n  - Caractère (majuscule)."
            description += f"\n  - Index de clé: {key_index} (pointe sur '{current_key_char}', décalage={key_shift})."
            description += f"\n  - Calcul: (ord('{char}') - {base} + {key_shift}) % 26 + {base} = {new_ord} ('{output_char}')."
            key_index += 1
        else:
            description += "\n  - Caractère non-alphabétique. Conservé tel quel."
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


# --- SIMULATE PLAYFAIR ---
def simulate_playfair_encrypt(text: str, key: str) -> dict:
    """
    Trace étape par étape du chiffrement de Playfair.

    Les digrammes sont formés sur le message ENTIER. L'ancienne version les
    formait mot par mot, ce qui produisait des paires absurdes ("A B" -> "GA AZ").
    """
    steps = []
    matrix = playfair.generate_playfair_matrix(key)
    step_counter = 1

    # --- PHASE 1 : matrice ---
    steps.append({
        "step": step_counter,
        "phase": "Matrice",
        "description": (
            f"Construction de la matrice 5x5 à partir de la clé '{key}'.\n"
            f"  - Les lettres de la clé sont placées en premier, sans doublon.\n"
            f"  - Puis l'alphabet restant, dans l'ordre.\n"
            f"  - I et J partagent la même case."
        ),
        "matrix": matrix,
    })
    step_counter += 1

    # --- PHASE 2 : normalisation ---
    letters = playfair.normalise(text)
    steps.append({
        "step": step_counter,
        "phase": "Normalisation",
        "description": (
            f"Texte d'origine : '{text}'\n"
            f"On ne garde que les lettres, en majuscules, J devient I.\n"
            f"Résultat : '{letters}'\n"
            f"Playfair ne conserve ni les espaces ni la ponctuation : c'est une "
            f"propriété de l'algorithme, pas une limite de l'implémentation."
        ),
        "intermediate_result": letters,
    })
    step_counter += 1

    # --- PHASE 3 : découpage en digrammes ---
    digrams = playfair.build_digrams(text)
    steps.append({
        "step": step_counter,
        "phase": "Digrammes",
        "description": (
            f"Découpage du message entier en {len(digrams)} digrammes.\n"
            f"  - Une paire de lettres identiques est séparée par un 'X'.\n"
            f"  - Une longueur impaire est complétée par un 'X' final.\n"
            f"Digrammes : {' '.join(digrams)}"
        ),
        "digrams": digrams,
    })
    step_counter += 1

    # --- PHASE 4 : chiffrement, digramme par digramme ---
    result = ""
    for pair in digrams:
        char1, char2 = pair[0], pair[1]
        r1, c1 = playfair.find_position(matrix, char1)
        r2, c2 = playfair.find_position(matrix, char2)

        description = (
            f"Digramme '{pair}'.\n"
            f"  - '{char1}' est en ({r1}, {c1}).\n"
            f"  - '{char2}' est en ({r2}, {c2})."
        )

        if r1 == r2:
            rule = "Même ligne"
            new_pair = matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
            description += (
                f"\n  - RÈGLE : même ligne, on décale d'une case vers la droite."
                f"\n  - '{char1}' ({r1},{c1}) -> '{new_pair[0]}' ({r1},{(c1 + 1) % 5})."
                f"\n  - '{char2}' ({r2},{c2}) -> '{new_pair[1]}' ({r2},{(c2 + 1) % 5})."
            )
        elif c1 == c2:
            rule = "Même colonne"
            new_pair = matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
            description += (
                f"\n  - RÈGLE : même colonne, on décale d'une case vers le bas."
                f"\n  - '{char1}' ({r1},{c1}) -> '{new_pair[0]}' ({(r1 + 1) % 5},{c1})."
                f"\n  - '{char2}' ({r2},{c2}) -> '{new_pair[1]}' ({(r2 + 1) % 5},{c2})."
            )
        else:
            rule = "Rectangle"
            new_pair = matrix[r1][c2] + matrix[r2][c1]
            description += (
                f"\n  - RÈGLE : rectangle, on échange les colonnes."
                f"\n  - '{char1}' ({r1},{c1}) -> '{new_pair[0]}' ({r1},{c2})."
                f"\n  - '{char2}' ({r2},{c2}) -> '{new_pair[1]}' ({r2},{c1})."
            )

        result += new_pair
        steps.append({
            "step": step_counter,
            "phase": "Chiffrement",
            "description": description,
            "rule": rule,
            "input_digram": pair,
            "output_digram": new_pair,
            "positions": [[r1, c1], [r2, c2]],
            "intermediate_result": result,
        })
        step_counter += 1

    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": (
            f"Fin du chiffrement. Résultat : '{result}'.\n"
            f"Au déchiffrement, les 'X' de bourrage seront retirés."
        ),
        "final_result": result,
    })

    return {
        "final_result": result,
        "steps": steps,
        "matrix": matrix,
        "digrams": digrams,
        "input_text": text,
    }


# --- SIMULATE RAIL FENCE (le vrai zigzag) ---
def simulate_rail_fence_encrypt(text: str, rails: int) -> dict:
    """
    Trace étape par étape du Rail Fence : le texte est écrit en zigzag sur
    `rails` lignes, puis relu ligne par ligne.

    L'ancienne version de cette fonction simulait une transposition par
    colonnes — voir `simulate_columnar_encrypt`.
    """
    if rails <= 1:
        return {
            "final_result": text,
            "steps": [{
                "step": 0,
                "phase": "Erreur",
                "description": "Le nombre de rails doit être supérieur à 1.",
            }],
        }

    steps = []
    step_counter = 0

    steps.append({
        "step": step_counter,
        "phase": "Initialisation",
        "description": (
            f"Texte : '{text}' ({len(text)} caractères)\n"
            f"Nombre de rails : {rails}\n"
            f"Le texte descend puis remonte le long de la clôture. Aucun "
            f"caractère n'est ajouté ni supprimé : l'aller-retour est exact."
        ),
        "input_text": text,
    })
    step_counter += 1

    # --- PHASE 1 : écriture en zigzag ---
    grid = [["" for _ in range(len(text))] for _ in range(rails)]
    pattern = rail_fence._rail_pattern(len(text), rails)

    for column, (char, rail) in enumerate(zip(text, pattern, strict=True)):
        grid[rail][column] = char
        if column == 0:
            direction = "départ"
        elif pattern[column - 1] < rail:
            direction = "descente"
        else:
            direction = "remontée"
        steps.append({
            "step": step_counter,
            "phase": "Écriture",
            "description": (
                f"'{char}' placée sur le rail {rail}, colonne {column} ({direction})."
            ),
            "matrix": [row[:] for row in grid],
            "current_char": char,
            "current_pos": [rail, column],
        })
        step_counter += 1

    # --- PHASE 2 : lecture ligne par ligne ---
    cipher_text = ""
    for rail in range(rails):
        row_chars = "".join(c for c in grid[rail] if c)
        cipher_text += row_chars
        steps.append({
            "step": step_counter,
            "phase": "Lecture",
            "description": f"Lecture du rail {rail}, de gauche à droite : '{row_chars}'.",
            "matrix": grid,
            "current_pos": [rail, -1],
            "intermediate_result": cipher_text,
        })
        step_counter += 1

    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Résultat : '{cipher_text}'.",
        "final_result": cipher_text,
        "matrix": grid,
    })

    return {"final_result": cipher_text, "steps": steps, "matrix": grid}


# --- SIMULATE TRANSPOSITION PAR COLONNES ---
def simulate_columnar_encrypt(text: str, key: str) -> dict:
    """
    Trace étape par étape de la transposition par colonnes : le texte est
    écrit ligne par ligne, puis les colonnes sont relues dans l'ordre
    alphabétique des lettres de la clé.
    """
    steps = []
    step_counter = 0

    order = columnar.key_order(key)
    width = len(order)
    grid, _ = columnar.columnar_grid(text, key)
    key_letters = [c.upper() for c in key if not c.isspace()]

    # Rang de lecture de chaque colonne, pour l'affichage sous la clé.
    ranks = [0] * width
    for rank, col in enumerate(order, start=1):
        ranks[col] = rank

    steps.append({
        "step": step_counter,
        "phase": "Initialisation",
        "description": (
            f"Texte : '{text}' ({len(text)} caractères)\n"
            f"Clé : '{key}' -> grille de {width} colonnes.\n"
            f"Ordre de lecture (alphabétique) : "
            + "  ".join(f"{key_letters[c]}={ranks[c]}" for c in range(width))
        ),
        "input_text": text,
        "key_letters": key_letters,
        "column_ranks": ranks,
    })
    step_counter += 1

    # --- PHASE 1 : écriture ligne par ligne ---
    steps.append({
        "step": step_counter,
        "phase": "Écriture",
        "description": (
            f"Le texte est écrit ligne par ligne sur {len(grid)} lignes.\n"
            f"Les cases manquantes de la dernière ligne restent vides : aucun "
            f"bourrage n'est ajouté, la transposition reste donc réversible."
        ),
        "matrix": [row[:] for row in grid],
        "key_letters": key_letters,
        "column_ranks": ranks,
    })
    step_counter += 1

    # --- PHASE 2 : lecture des colonnes dans l'ordre de la clé ---
    cipher_text = ""
    for rank, col in enumerate(order, start=1):
        column_chars = "".join(row[col] for row in grid if row[col])
        cipher_text += column_chars
        steps.append({
            "step": step_counter,
            "phase": "Lecture",
            "description": (
                f"Rang {rank} : colonne {col}, lettre '{key_letters[col]}' de la clé "
                f"-> '{column_chars}'."
            ),
            "matrix": grid,
            "current_column": col,
            "key_letters": key_letters,
            "column_ranks": ranks,
            "intermediate_result": cipher_text,
        })
        step_counter += 1

    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Résultat : '{cipher_text}'.",
        "final_result": cipher_text,
        "matrix": grid,
    })

    return {"final_result": cipher_text, "steps": steps, "matrix": grid}


# --- SIMULATE SHA-256 ---
def simulate_sha256(text: str) -> dict:
    """
    Trace étape par étape de SHA-256 (FIPS 180-4) : bourrage, découpage en
    blocs de 512 bits, extension du planning des messages (W[0..63]) et les
    64 tours de la fonction de compression pour chaque bloc.

    Contrairement à `hash_tool.hash_sha256` (hashlib, chemin de production),
    cette fonction recalcule tout depuis zéro pour exposer chaque tour.
    """
    steps = []
    step_counter = 0

    data = text.encode("utf-8")
    padded = sha256_tool.pad_message(data)
    blocks = [padded[i:i + 64] for i in range(0, len(padded), 64)]

    steps.append({
        "step": step_counter,
        "phase": "Bourrage",
        "description": (
            f"Texte : '{text}' ({len(data)} octets, {len(data) * 8} bits).\n"
            f"Bourrage : un bit '1', puis des zéros, puis la longueur "
            f"d'origine sur 64 bits — jusqu'à un multiple de 512 bits.\n"
            f"Message bourré : {len(padded) * 8} bits, soit {len(blocks)} "
            f"bloc(s) de 512 bits."
        ),
        "input_text": text,
        "block_count": len(blocks),
    })
    step_counter += 1

    h = sha256_tool.H0
    for block_index, block in enumerate(blocks):
        w = sha256_tool.message_schedule(block)
        steps.append({
            "step": step_counter,
            "phase": "Planning des messages",
            "description": (
                f"Bloc {block_index} : les 16 premiers mots W[0..15] viennent "
                f"directement du bloc. W[16..63] sont dérivés par rotations et "
                f"décalages des mots précédents (formule σ0/σ1, FIPS 180-4 §4.1.2)."
            ),
            "block": block_index,
            "schedule": [f"{word:08x}" for word in w],
        })
        step_counter += 1

        h_before = h
        new_h, rounds = sha256_tool.compress(h, w)

        steps.append({
            "step": step_counter,
            "phase": "État initial",
            "description": (
                f"Bloc {block_index} : variables de travail a..h initialisées "
                f"à l'état courant du condensé."
            ),
            "block": block_index,
            "state": {
                name: f"{value:08x}"
                for name, value in zip("abcdefgh", h_before, strict=True)
            },
        })
        step_counter += 1

        for round_info in rounds:
            state_hex = {k: f"{v:08x}" for k, v in round_info["state"].items()}
            steps.append({
                "step": step_counter,
                "phase": "Compression",
                "description": (
                    f"Bloc {block_index}, tour {round_info['round']} : "
                    f"Ch(e,f,g) et Maj(a,b,c) combinent W[{round_info['round']}] "
                    f"({round_info['w']:08x}) et la constante K[{round_info['round']}] "
                    f"({round_info['k']:08x}) pour produire les nouvelles "
                    f"variables de travail."
                ),
                "block": block_index,
                "round": round_info["round"],
                "state": state_hex,
            })
            step_counter += 1

        h = new_h
        steps.append({
            "step": step_counter,
            "phase": "Mise à jour du condensé",
            "description": (
                f"Bloc {block_index} terminé : chaque variable de travail "
                f"est additionnée (mod 2^32) à l'état précédent du condensé."
            ),
            "block": block_index,
            "digest_state": [f"{word:08x}" for word in h],
        })
        step_counter += 1

    result = sha256_tool.digest_hex(h)
    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Empreinte : '{result}'.",
        "final_result": result,
    })

    return {"final_result": result, "steps": steps, "block_count": len(blocks)}


# --- SIMULATE SHA-1 ---
def simulate_sha1(text: str) -> dict:
    """
    Trace étape par étape de SHA-1 (FIPS 180-1 / RFC 3174) : même structure que
    `simulate_sha256`, avec 80 tours par bloc au lieu de 64 et un état sur cinq
    mots (a..e) au lieu de huit.

    SHA-1 est CASSÉ (attaque SHAttered, 2017) : cette trace sert à comprendre
    la construction Merkle-Damgård qu'il partage avec SHA-256, jamais à
    justifier son usage en production.
    """
    steps = []
    step_counter = 0

    data = text.encode("utf-8")
    padded = sha1_tool.pad_message(data)
    blocks = [padded[i:i + 64] for i in range(0, len(padded), 64)]

    steps.append({
        "step": step_counter,
        "phase": "Bourrage",
        "description": (
            f"Texte : '{text}' ({len(data)} octets, {len(data) * 8} bits). "
            f"SHA-1 est CASSÉ depuis 2017 (attaque SHAttered) : cette trace "
            f"est pédagogique, pas une recommandation d'usage.\n"
            f"Bourrage identique dans sa forme à SHA-256 : un bit '1', des "
            f"zéros, puis la longueur d'origine sur 64 bits.\n"
            f"Message bourré : {len(padded) * 8} bits, soit {len(blocks)} "
            f"bloc(s) de 512 bits."
        ),
        "input_text": text,
        "block_count": len(blocks),
    })
    step_counter += 1

    h = sha1_tool.H0
    for block_index, block in enumerate(blocks):
        w = sha1_tool.message_schedule(block)
        steps.append({
            "step": step_counter,
            "phase": "Planning des messages",
            "description": (
                f"Bloc {block_index} : les 16 premiers mots W[0..15] viennent "
                f"du bloc. W[16..79] sont dérivés par XOR et rotation gauche "
                f"de 1 bit des mots précédents (RFC 3174 §6.1)."
            ),
            "block": block_index,
            "schedule": [f"{word:08x}" for word in w],
        })
        step_counter += 1

        h_before = h
        new_h, rounds = sha1_tool.compress(h, w)

        steps.append({
            "step": step_counter,
            "phase": "État initial",
            "description": (
                f"Bloc {block_index} : variables de travail a..e initialisées "
                f"à l'état courant du condensé."
            ),
            "block": block_index,
            "state": {
                name: f"{value:08x}"
                for name, value in zip("abcde", h_before, strict=True)
            },
        })
        step_counter += 1

        for round_info in rounds:
            state_hex = {k: f"{v:08x}" for k, v in round_info["state"].items()}
            steps.append({
                "step": step_counter,
                "phase": "Compression",
                "description": (
                    f"Bloc {block_index}, tour {round_info['round']} : la "
                    f"fonction f (Ch, Parity ou Maj selon la plage du tour) "
                    f"combine W[{round_info['round']}] "
                    f"({round_info['w']:08x}) et la constante K "
                    f"({round_info['k']:08x})."
                ),
                "block": block_index,
                "round": round_info["round"],
                "state": state_hex,
            })
            step_counter += 1

        h = new_h
        steps.append({
            "step": step_counter,
            "phase": "Mise à jour du condensé",
            "description": (
                f"Bloc {block_index} terminé : chaque variable de travail "
                f"est additionnée (mod 2^32) à l'état précédent du condensé."
            ),
            "block": block_index,
            "digest_state": [f"{word:08x}" for word in h],
        })
        step_counter += 1

    result = sha1_tool.digest_hex(h)
    steps.append({
        "step": step_counter,
        "phase": "Final",
        "description": f"Fin du processus. Empreinte : '{result}'.",
        "final_result": result,
    })

    return {"final_result": result, "steps": steps, "block_count": len(blocks)}
