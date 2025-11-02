from . import des_constants as const
from typing import List, Dict, Any


# --- Fonctions "Helpers" pour la manipulation de bits ---

def permute(bits: str, table: List[int]) -> str:
    """Applique une table de permutation à une chaîne de bits."""
    # Les tables de 'const' sont indexées à 1
    return "".join(bits[i - 1] for i in table)


def xor(bits1: str, bits2: str) -> str:
    """Effectue un XOR entre deux chaînes de bits."""
    return "".join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))


def shift_left(bits: str, n: int) -> str:
    """Effectue un décalage circulaire à gauche de n bits."""
    return bits[n:] + bits[:n]


def text_to_bits(text: str) -> str:
    """Convertit une chaîne de 8 caractères (64 bits) en chaîne de bits."""
    if len(text) > 8:
        text = text[:8]  # Tronque à 8 caractères
    # Pad avec des espaces si plus court que 8
    text = text.ljust(8, ' ')

    bits = ""
    for char in text:
        # '08b' = formater en binaire sur 8 bits, avec 'padding' de 0
        bits += format(ord(char), '08b')
    return bits


def key_to_bits(key: str) -> str:
    """Convertit une clé de 8 caractères (64 bits) en chaîne de bits."""
    if len(key) > 8:
        key = key[:8]
    key = key.ljust(8, ' ')

    bits = ""
    for char in key:
        bits += format(ord(char), '08b')
    return bits


def bits_to_hex(bits: str) -> str:
    """Convertit une chaîne de bits en sa représentation hexadécimale."""
    return f'{int(bits, 2):X}'.zfill(len(bits) // 4)


# --- Logique de la Fonction F (le cœur d'un round) ---

def f_function(right_half: str, round_key: str, s_box_steps: List) -> str:
    """
    Exécute la fonction F de Feistel.
    (32 bits Right + 48 bits Key) -> 32 bits Output
    """

    # 1. Expansion (E): 32 bits -> 48 bits
    expanded = permute(right_half, const.E)
    f_step_desc = f"  1. Expansion (E): 32 bits -> 48 bits.\n     {right_half} -> {expanded}"

    # 2. XOR avec la clé de round (K)
    xored = xor(expanded, round_key)
    f_step_desc += f"\n  2. XOR avec Clé K: 48 bits XOR 48 bits.\n     {expanded} \n     XOR \n     {round_key} \n     = \n     {xored}"

    # 3. Substitution (S-Boxes): 48 bits -> 32 bits
    s_box_output = ""
    s_box_details = []
    # Traite les 8 S-Boxes (6 bits chacune)
    for i in range(8):
        s_input = xored[i * 6: (i + 1) * 6]

        # Le 1er et 6e bit déterminent la ligne
        row_bits = s_input[0] + s_input[5]
        row = int(row_bits, 2)

        # Les 4 bits du milieu déterminent la colonne
        col_bits = s_input[1:5]
        col = int(col_bits, 2)

        # Recherche dans la S-Box
        s_value = const.S_BOX[i][row][col]

        # Convertir la valeur (0-15) en 4 bits
        s_output_bits = format(s_value, '04b')
        s_box_output += s_output_bits

        s_box_details.append(
            f"S{i + 1}: In='{s_input}', Ligne={row} ('{row_bits}'), Col={col} ('{col_bits}') -> Val={s_value} -> Out='{s_output_bits}'"
        )

    s_box_steps.append({"details": s_box_details, "full_output": s_box_output})
    f_step_desc += f"\n  3. S-Boxes: 48 bits -> 32 bits.\n     (Détails dans 's_box_trace') -> {s_box_output}"

    # 4. Permutation (P): 32 bits -> 32 bits
    f_output = permute(s_box_output, const.P)
    f_step_desc += f"\n  4. Permutation (P): 32 bits -> 32 bits.\n     {s_box_output} -> {f_output}"

    return f_output, f_step_desc


# --- Générateur des clés de round (Key Schedule) ---

def generate_round_keys(key_bits_64: str) -> (List[str], List[Dict]):
    """
    Génère les 16 clés de round (48 bits) à partir de la clé de 64 bits.
    Retourne la liste des clés et la trace de simulation.
    """
    round_keys = []
    key_steps = []

    # 1. PC1 (Permuted Choice 1): 64 bits -> 56 bits
    key_56 = permute(key_bits_64, const.PC1)
    key_steps.append({
        "step": "KS-1 (PC1)",
        "description": f"Clé 64 bits permutée avec PC1 -> 56 bits.\n{key_bits_64} -> {key_56}"
    })

    # 2. Séparation en C (gauche) et D (droite)
    C = key_56[:28]
    D = key_56[28:]
    key_steps.append({
        "step": "KS-2 (Split C/D)",
        "description": f"Division en C0 (28 bits) et D0 (28 bits).\nC0 = {C}\nD0 = {D}"
    })

    # 3. 16 Rounds de décalage et PC2
    for i in range(16):
        round_num = i + 1

        # 3a. Décalage (Shift)
        shift_val = const.SHIFT[i]
        C = shift_left(C, shift_val)
        D = shift_left(D, shift_val)

        shift_desc = f"Round {round_num}: Décalage de {shift_val} bit(s).\nC{round_num} = {C}\nD{round_num} = {D}"

        # 3b. Combinaison et PC2 (Permuted Choice 2)
        CD = C + D
        K_i = permute(CD, const.PC2)  # Clé de round de 48 bits
        round_keys.append(K_i)

        key_steps.append({
            "step": f"KS-3 (Round {round_num})",
            "description": f"{shift_desc}\nCombinaison C+D (56 bits) -> PC2 -> K{round_num} (48 bits).\n{CD} -> {K_i}"
        })

    return round_keys, key_steps


# --- Simulateur Principal ---

def simulate_des_encrypt(plain_text_str: str, key_str: str) -> dict:
    """
    Fonction principale de simulation du chiffrement DES.
    Prend un texte et une clé (8 chars max), retourne une trace complète.
    """

    steps = []
    s_box_traces = []  # Trace séparée pour les S-Boxes

    # --- Phase 0: Pré-traitement ---
    plain_bits_64 = text_to_bits(plain_text_str)
    key_bits_64 = key_to_bits(key_str)

    steps.append({
        "phase": "Pré-traitement",
        "step": 0,
        "description": f"Conversion du texte et de la clé en blocs de 64 bits.\nTexte: '{plain_text_str}' -> {plain_bits_64}\nClé:   '{key_str}' -> {key_bits_64}"
    })

    # --- Phase 1: Génération des Clés de Round ---
    steps.append({"phase": "Génération des Clés", "step": "KS-0", "description": "Démarrage du Key Schedule..."})
    round_keys, key_steps = generate_round_keys(key_bits_64)
    steps.extend(key_steps)  # Ajoute toutes les étapes de génération de clé

    # --- Phase 2: Chiffrement du Bloc ---

    # 1. Permutation Initiale (IP)
    ip_bits = permute(plain_bits_64, const.IP)
    steps.append({
        "phase": "Chiffrement",
        "step": 1,
        "description": f"Permutation Initiale (IP) sur le bloc de 64 bits.\n{plain_bits_64} -> {ip_bits}"
    })

    # 2. Séparation en L0 (gauche) et R0 (droite)
    L = ip_bits[:32]
    R = ip_bits[32:]
    steps.append({
        "phase": "Chiffrement",
        "step": 2,
        "description": f"Séparation en L0 (32 bits) et R0 (32 bits).\nL0 = {L}\nR0 = {R}"
    })

    # 3. 16 Rounds de Feistel
    for i in range(16):
        round_num = i + 1
        L_prev, R_prev = L, R

        # Logique de Feistel: L_i = R_{i-1}
        L = R_prev

        # Logique de Feistel: R_i = L_{i-1} XOR F(R_{i-1}, K_i)
        K_i = round_keys[i]

        # Appel de la fonction F
        s_box_trace_for_round = []
        f_output, f_step_desc = f_function(R_prev, K_i, s_box_trace_for_round)

        R = xor(L_prev, f_output)

        # Sauvegarde des traces
        s_box_traces.append({
            "round": round_num,
            "trace": s_box_trace_for_round[0]  # s_box_trace_for_round est une liste avec 1 élément dict
        })

        steps.append({
            "phase": "Chiffrement",
            "step": f"Round {round_num}",
            "description": (
                f"L{round_num - 1} = {L_prev}\nR{round_num - 1} = {R_prev}\nK{round_num} = {K_i}\n\n"
                f"Calcul de la Fonction F(R{round_num - 1}, K{round_num}):\n{f_step_desc}\n\n"
                f"Calcul de L{round_num} et R{round_num}:\n"
                f"L{round_num} = R{round_num - 1} = {R_prev}\n"
                f"R{round_num} = L{round_num - 1} XOR F(...) = {L_prev} XOR {f_output} = {R}"
            ),
            f"L{round_num}": L,
            f"R{round_num}": R
        })

    # 4. Swap final (R16, L16)
    final_block_before_perm = R + L  # Note: R vient avant L
    steps.append({
        "phase": "Chiffrement",
        "step": "Final Swap",
        "description": f"Fin des 16 rounds. Recombinaison finale (R16, L16).\nR16 = {R}\nL16 = {L}\nBloc (R16+L16) = {final_block_before_perm}"
    })

    # 5. Permutation Finale (IP-1)
    cipher_bits = permute(final_block_before_perm, const.IP_1)
    cipher_hex = bits_to_hex(cipher_bits)

    steps.append({
        "phase": "Final",
        "step": "IP-1",
        "description": f"Application de la Permutation Finale (IP-1).\n{final_block_before_perm} -> {cipher_bits}"
    })

    return {
        "final_result_bits": cipher_bits,
        "final_result_hex": cipher_hex,
        "steps": steps,
        "s_box_traces": s_box_traces
    }