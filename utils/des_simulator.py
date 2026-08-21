
from . import des_constants as const

# --- Fonctions "Helpers" pour la manipulation de bits ---

def permute(bits: str, table: list[int]) -> str:
    """Applique une table de permutation à une chaîne de bits."""
    # Les tables de 'const' sont indexées à 1
    return "".join(bits[i - 1] for i in table)


def xor(bits1: str, bits2: str) -> str:
    """Effectue un XOR entre deux chaînes de bits."""
    return "".join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2, strict=True))


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

def f_function(right_half: str, round_key: str, s_box_steps: list) -> str:
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

def generate_round_keys(key_bits_64: str) -> (list[str], list[dict]):
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


# --- Bourrage PKCS#7 (bloc de 8 octets) --------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Longueur invalide pour un dépadding PKCS#7.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bourrage PKCS#7 invalide.")
    return data[:-pad_len]


# --- Chiffrement / déchiffrement d'un bloc brut de 8 octets ------------------
# Le réseau de Feistel de DES est sa propre inverse : dérouler les 16 rounds
# avec les clés dans l'ordre inverse (K16..K1) déchiffre exactement ce que
# l'ordre K1..K16 a chiffré. C'est la propriété centrale que cette fonction
# rend visible : chiffrer et déchiffrer, c'est le même circuit.

def _feistel_rounds(bits_64: str, round_keys: list[str], *, reverse: bool) -> tuple[str, list[dict], list[dict]]:
    steps = []
    s_box_traces = []

    ip_bits = permute(bits_64, const.IP)
    steps.append({"phase": "Permutation Initiale (IP)",
                  "description": f"{bits_64} -> {ip_bits}"})

    L, R = ip_bits[:32], ip_bits[32:]
    keys_in_order = list(reversed(round_keys)) if reverse else round_keys

    for i in range(16):
        round_num = i + 1
        L_prev, R_prev = L, R
        L = R_prev
        K_i = keys_in_order[i]

        s_box_trace_for_round = []
        f_output, f_step_desc = f_function(R_prev, K_i, s_box_trace_for_round)
        R = xor(L_prev, f_output)

        s_box_traces.append({"round": round_num, "trace": s_box_trace_for_round[0]})
        steps.append({
            "phase": "Déchiffrement" if reverse else "Chiffrement",
            "round": round_num,
            "description": f"Round {round_num} : {f_step_desc}",
        })

    final_block = R + L
    cipher_bits = permute(final_block, const.IP_1)
    steps.append({"phase": "Permutation Finale (IP-1)",
                  "description": f"{final_block} -> {cipher_bits}"})
    return cipher_bits, steps, s_box_traces


def encrypt_block_bits(bits_64: str, round_keys: list[str]) -> tuple[str, list[dict]]:
    result, steps, _ = _feistel_rounds(bits_64, round_keys, reverse=False)
    return result, steps


def decrypt_block_bits(bits_64: str, round_keys: list[str]) -> tuple[str, list[dict]]:
    """
    Déchiffre un bloc de 64 bits : mêmes 16 rounds de Feistel, mais les clés
    de round sont appliquées dans l'ordre inverse (K16 en premier).
    """
    result, steps, _ = _feistel_rounds(bits_64, round_keys, reverse=True)
    return result, steps


# --- Simulation multi-blocs ---------------------------------------------------
# L'ancien simulateur ne traitait qu'un bloc de 8 caractères, tronquait
# silencieusement au-delà, et ne simulait que le chiffrement. Ici : bourrage
# PKCS#7 tracé, découpage en N blocs de 8 octets, chiffrement ET déchiffrement
# pas à pas (blocs chaînés en ECB — CBC/CTR sont couverts par `modes_tool`).

def simulate_des_encrypt_multiblock(plain_text: str, key_str: str) -> dict:
    key = key_str if len(key_str) <= 8 else key_str[:8]
    key = key.ljust(8, " ")
    key_bits_64 = key_to_bits(key)
    round_keys, key_steps = generate_round_keys(key_bits_64)

    plain_bytes = plain_text.encode("utf-8")
    padded = pkcs7_pad(plain_bytes, 8)
    blocks = [padded[i:i + 8] for i in range(0, len(padded), 8)]

    steps = [{
        "step": 0,
        "phase": "Bourrage PKCS#7",
        "description": (
            f"Texte : '{plain_text}' ({len(plain_bytes)} octets).\n"
            f"Bourrage PKCS#7 jusqu'à un multiple de 8 octets : "
            f"{padded[-1]} octet(s) ajouté(s).\n"
            f"Découpage en {len(blocks)} bloc(s) de 8 octets."
        ),
        "block_count": len(blocks),
    }]
    steps.extend(key_steps)

    cipher_bytes = b""
    block_results = []
    for index, block in enumerate(blocks):
        block_bits = "".join(format(byte, "08b") for byte in block)
        cipher_bits, block_steps = encrypt_block_bits(block_bits, round_keys)
        cipher_block = bytes(int(cipher_bits[i:i + 8], 2) for i in range(0, 64, 8))
        cipher_bytes += cipher_block
        for s in block_steps:
            s["block"] = index
        steps.append({
            "step": len(steps),
            "phase": "Bloc",
            "block": index,
            "description": f"--- Bloc {index} ({block.hex()}) ---",
            "block_steps": block_steps,
            "block_result_hex": cipher_block.hex().upper(),
        })
        block_results.append(cipher_block.hex().upper())

    final_hex = cipher_bytes.hex().upper()
    steps.append({
        "step": len(steps),
        "phase": "Final",
        "description": f"Fin du chiffrement. Résultat ({len(blocks)} bloc(s)) : {final_hex}",
        "final_result_hex": final_hex,
    })

    return {
        "final_result_hex": final_hex,
        "block_count": len(blocks),
        "block_results": block_results,
        "steps": steps,
    }


def simulate_des_decrypt_multiblock(cipher_hex: str, key_str: str) -> dict:
    key = key_str if len(key_str) <= 8 else key_str[:8]
    key = key.ljust(8, " ")
    key_bits_64 = key_to_bits(key)
    round_keys, key_steps = generate_round_keys(key_bits_64)

    cipher_bytes = bytes.fromhex(cipher_hex)
    if len(cipher_bytes) % 8 != 0:
        raise ValueError("Le chiffré doit être un multiple de 8 octets.")
    blocks = [cipher_bytes[i:i + 8] for i in range(0, len(cipher_bytes), 8)]

    steps = list(key_steps)
    plain_padded = b""
    for index, block in enumerate(blocks):
        block_bits = "".join(format(byte, "08b") for byte in block)
        plain_bits, block_steps = decrypt_block_bits(block_bits, round_keys)
        plain_block = bytes(int(plain_bits[i:i + 8], 2) for i in range(0, 64, 8))
        plain_padded += plain_block
        for s in block_steps:
            s["block"] = index
        steps.append({
            "step": len(steps),
            "phase": "Bloc",
            "block": index,
            "description": f"--- Bloc {index} ({block.hex()}) ---",
            "block_steps": block_steps,
            "block_result_hex": plain_block.hex().upper(),
        })

    try:
        plain_bytes = pkcs7_unpad(plain_padded, 8)
    except ValueError as exc:
        raise ValueError(
            "Bourrage PKCS#7 invalide au déchiffrement : clé incorrecte, ou "
            "données altérées."
        ) from exc

    try:
        plain_text = plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Le résultat déchiffré n'est pas du texte UTF-8 valide.") from exc

    steps.append({
        "step": len(steps),
        "phase": "Dépadding",
        "description": (
            f"Retrait du bourrage PKCS#7 ({len(plain_padded) - len(plain_bytes)} "
            f"octets retirés).\nRésultat : '{plain_text}'."
        ),
        "final_result": plain_text,
    })

    return {
        "final_result": plain_text,
        "block_count": len(blocks),
        "steps": steps,
    }
