
from . import aes_constants as const
from .aes_math import gadd, gmul, mix_single_column

# --- Types de données ---
# Un "mot" (word) est une liste de 4 bytes [b0, b1, b2, b3]
Word = list[int]
# Un "état" (state) est une matrice 4x4 de bytes
State = list[list[int]]

# S-Box inverse, calculee une seule fois a l'import a partir de la S-Box
# directe (const.S_BOX[row][col] = value  =>  INV_S_BOX[value] = row*16+col).
INV_S_BOX = [0] * 256
for _row in range(16):
    for _col in range(16):
        INV_S_BOX[const.S_BOX[_row][_col]] = (_row << 4) | _col
del _row, _col


# --- Helpers de formatage ---

def text_to_state(text: str) -> (State, str):
    """Convertit un texte de 16 chars en un état 4x4 (colonne par colonne)."""
    # Pad ou tronque à 16 octets
    if len(text) > 16:
        text = text[:16]
    text_bytes = text.encode('utf-8').ljust(16, b'\x00')

    state = [[0 for _ in range(4)] for _ in range(4)]
    # Remplissage par colonne (format AES)
    for c in range(4):
        for r in range(4):
            state[r][c] = text_bytes[c * 4 + r]

    trace = f"Texte '{text}' converti en {len(text_bytes)} bytes.\nBytes (hex): {text_bytes.hex()}\nÉtat 4x4 (rempli par colonne) :\n{state_to_str(state)}"
    return state, trace


def key_to_words(key: str) -> (list[Word], str):
    """Convertit une clé de 16 chars en 4 mots de 4 bytes."""
    if len(key) > 16:
        key = key[:16]
    key_bytes = key.encode('utf-8').ljust(16, b'\x00')

    words = []
    for i in range(4):  # 4 mots
        word = list(key_bytes[i * 4: (i + 1) * 4])
        words.append(word)

    trace = f"Clé '{key}' convertie en {len(key_bytes)} bytes.\nBytes (hex): {key_bytes.hex()}\nMots initiaux (W0-W3): {words_to_str(words)}"
    return words, trace


def state_to_str(state: State) -> str:
    """Helper pour un affichage propre de l'état."""
    return "\n".join(f"  [{' '.join(f'{b:02x}' for b in row)}]" for row in state)


def words_to_str(words: list[Word]) -> str:
    """Helper pour un affichage propre des mots de clé."""
    return "\n".join(f"  {word}" for word in words)


# --- Opérations du Key Schedule ---

def sub_word(word: Word) -> Word:
    """Applique la S-Box à chaque byte d'un mot."""
    new_word = []
    for byte in word:
        row = (byte >> 4) & 0x0F
        col = byte & 0x0F
        new_word.append(const.S_BOX[row][col])
    return new_word


def rot_word(word: Word) -> Word:
    """Rotation circulaire à gauche d'un mot [b0, b1, b2, b3] -> [b1, b2, b3, b0]."""
    return word[1:] + word[:1]


def xor_words(w1: Word, w2: Word) -> Word:
    """XOR de deux mots, byte par byte."""
    return [gadd(b1, b2) for b1, b2 in zip(w1, w2, strict=True)]


# --- Opérations des Rounds AES ---

def sub_bytes(state: State, trace_list: list[str]) -> State:
    """Applique l'opération SubBytes (S-Box) à chaque byte de l'état."""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    desc = "Application de SubBytes (S-Box) sur chaque byte :"

    for r in range(4):
        row_desc_in = "  IN: ["
        row_desc_out = " OUT: ["
        for c in range(4):
            byte = state[r][c]
            row = (byte >> 4) & 0x0F
            col = byte & 0x0F
            new_byte = const.S_BOX[row][col]
            new_state[r][c] = new_byte

            row_desc_in += f"{byte:02x} "
            row_desc_out += f"{new_byte:02x} "
        desc += f"\n{row_desc_in.strip()}] -> {row_desc_out.strip()}]"

    trace_list.append(desc)
    return new_state


def shift_rows(state: State, trace_list: list[str]) -> State:
    """Applique l'opération ShiftRows (décalage des lignes)."""
    new_state = [row[:] for row in state]  # Copie
    desc = "Application de ShiftRows :"
    desc += f"\n  Ligne 0 (pas de décalage): {new_state[0]}"

    # Ligne 1: Décalage de 1 à gauche
    new_state[1] = state[1][1:] + state[1][:1]
    desc += f"\n  Ligne 1 (décalage de 1): {new_state[1]}"

    # Ligne 2: Décalage de 2 à gauche
    new_state[2] = state[2][2:] + state[2][:2]
    desc += f"\n  Ligne 2 (décalage de 2): {new_state[2]}"

    # Ligne 3: Décalage de 3 à gauche (ou 1 à droite)
    new_state[3] = state[3][3:] + state[3][:3]
    desc += f"\n  Ligne 3 (décalage de 3): {new_state[3]}"

    trace_list.append(desc)
    return new_state


def mix_columns(state: State, trace_list: list[str]) -> State:
    """Applique l'opération MixColumns (multiplication de matrice GF(2^8))."""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    desc = "Application de MixColumns (multiplication de matrice GF(2^8) par colonne) :"

    for c in range(4):
        col_in = [state[r][c] for r in range(4)]
        col_out = mix_single_column(col_in)
        desc += f"\n  Colonne {c}: {col_in} -> {col_out}"
        for r in range(4):
            new_state[r][c] = col_out[r]

    trace_list.append(desc)
    return new_state


def add_round_key(state: State, round_key: State, trace_list: list[str]) -> State:
    """Applique AddRoundKey (XOR avec la clé de round)."""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    desc = "Application de AddRoundKey (XOR avec la clé de round) :"

    for r in range(4):
        desc_row = " "
        for c in range(4):
            val = gadd(state[r][c], round_key[r][c])
            new_state[r][c] = val
            desc_row += f" {state[r][c]:02x} ^ {round_key[r][c]:02x} = {val:02x} |"
        desc += f"\n  Ligne {r}: |{desc_row}"

    trace_list.append(desc)
    return new_state


# --- Générateur des clés de round (Key Schedule) ---

def expand_key(key_words: list[Word]) -> (list[State], list[dict]):
    """Génère les 11 clés de round (44 mots) pour AES-128."""

    w = list(key_words)  # Commence avec W0, W1, W2, W3
    key_schedule_trace = [{
        "step": "KS-0",
        "description": f"Clé de base (W0-W3):\n{words_to_str(w)}"
    }]

    for i in range(4, 44):  # Génère W4 à W43
        temp = list(w[i - 1])  # Mot précédent (ex: W3 pour i=4)
        w_prev4 = w[i - 4]  # Mot W[i-4] (ex: W0 pour i=4)

        desc = f"Génération de W{i}:\n  temp = W{i - 1} = {temp}\n  w_prev4 = W{i - 4} = {w_prev4}"

        if i % 4 == 0:
            # C'est ici que la magie opère (pour W4, W8, W12...)
            temp = rot_word(temp)
            desc_rot = f"temp = RotWord(temp) -> {temp}"

            temp = sub_word(temp)
            desc_sub = f"temp = SubWord(temp) -> {temp}"

            rcon = const.RCON[i // 4]
            desc_rcon = f"RCON[{i // 4}] = {rcon}"

            temp = xor_words(temp, rcon)
            desc += f"\n  {desc_rot}\n  {desc_sub}\n  {desc_rcon}\n  temp = temp ^ RCON -> {temp}"

        # Calcul final: W[i] = W[i-4] XOR temp
        new_word = xor_words(w_prev4, temp)
        w.append(new_word)
        desc += f"\n  W{i} = w_prev4 ^ temp -> {new_word}"

        key_schedule_trace.append({"step": f"KS-{i}", "description": desc})

    # Convertir la liste de 44 mots en 11 clés de round (matrice State 4x4)
    round_keys_state = []
    for i in range(11):
        key_state = [[0 for _ in range(4)] for _ in range(4)]
        # Ré-assemble les 4 mots en une matrice (par colonne)
        w0, w1, w2, w3 = w[i * 4], w[i * 4 + 1], w[i * 4 + 2], w[i * 4 + 3]
        for r in range(4):
            key_state[r][0] = w0[r]
            key_state[r][1] = w1[r]
            key_state[r][2] = w2[r]
            key_state[r][3] = w3[r]
        round_keys_state.append(key_state)

    return round_keys_state, key_schedule_trace


# --- Simulateur Principal ---

def simulate_aes_encrypt(plain_text_str: str, key_str: str) -> dict:
    steps = []

    # --- Phase 0: Pré-traitement ---
    state, prep_trace_text = text_to_state(plain_text_str)
    steps.append({"phase": "Pré-traitement (Texte)", "step": 0, "description": prep_trace_text,
                  "state_hex": state_to_str(state)})

    key_words, prep_trace_key = key_to_words(key_str)
    steps.append({"phase": "Pré-traitement (Clé)", "step": 0, "description": prep_trace_key})

    # --- Phase 1: Génération des Clés de Round (Key Schedule) ---
    steps.append(
        {"phase": "Génération des Clés", "step": "KS-Start", "description": "Démarrage du Key Schedule AES-128..."})
    round_keys, key_schedule_trace = expand_key(key_words)
    steps.extend(key_schedule_trace)

    # --- Phase 2: Chiffrement ---

    # Round 0 (Initial): AddRoundKey
    round_trace = []
    state = add_round_key(state, round_keys[0], round_trace)
    steps.append({
        "phase": "Chiffrement",
        "round": 0,
        "description": "Round 0 (Pré-calcul):\n" + "\n".join(round_trace),
        "state_hex": state_to_str(state)
    })

    # Rounds 1 à 9 (Principaux)
    for r in range(1, 10):
        round_trace = []
        state = sub_bytes(state, round_trace)
        state_sub = state

        state = shift_rows(state, round_trace)
        state_shift = state

        state = mix_columns(state, round_trace)
        state_mix = state

        state = add_round_key(state, round_keys[r], round_trace)
        state_addkey = state

        steps.append({
            "phase": "Chiffrement",
            "round": r,
            "description": f"--- Round {r} ---\n" + "\n\n".join(round_trace),
            "sub_bytes_out": state_to_str(state_sub),
            "shift_rows_out": state_to_str(state_shift),
            "mix_columns_out": state_to_str(state_mix),
            "add_round_key_out": state_to_str(state_addkey)
        })

    # Round 10 (Final) - Pas de MixColumns
    round_trace = []
    state = sub_bytes(state, round_trace)
    state_sub = state

    state = shift_rows(state, round_trace)
    state_shift = state

    # Pas de MixColumns
    round_trace.append("MixColumns: [OMIS (Round Final)]")

    state = add_round_key(state, round_keys[10], round_trace)
    state_addkey = state

    steps.append({
        "phase": "Chiffrement",
        "round": 10,
        "description": "--- Round 10 (Final) ---\n" + "\n\n".join(round_trace),
        "sub_bytes_out": state_to_str(state_sub),
        "shift_rows_out": state_to_str(state_shift),
        "mix_columns_out": "N/A",
        "add_round_key_out": state_to_str(state_addkey)
    })

    # Final
    final_hex = "".join(f"{state[r][c]:02x}" for c in range(4) for r in range(4))
    steps.append({
        "phase": "Final",
        "round": "N/A",
        "description": f"Fin du chiffrement. Résultat (lu par colonne) : {final_hex}",
        "final_result_hex": final_hex
    })

    return {"final_result_hex": final_hex, "steps": steps}


# --- Bourrage PKCS#7 (RFC 5652 §6.3) -----------------------------------------
# Necessaire pour chiffrer un message de longueur quelconque en plusieurs
# blocs de 16 octets : le dernier bloc est complete par des octets dont la
# valeur est elle-meme la quantite de bourrage ajoutee (ex: message qui tombe
# juste sur un multiple de 16 -> un bloc ENTIER de 0x10 est ajoute, jamais
# zero bourrage, sinon le dechiffrement ne pourrait pas distinguer bourrage et
# absence de bourrage).

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Longueur invalide pour un dépadding PKCS#7.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bourrage PKCS#7 invalide.")
    return data[:-pad_len]


# --- Transformations inverses (déchiffrement) --------------------------------

def inv_sub_bytes(state: State, trace_list: list[str]) -> State:
    """InvSubBytes : S-Box inverse sur chaque byte."""
    new_state = [[0] * 4 for _ in range(4)]
    desc = "Application de InvSubBytes (S-Box inverse) sur chaque byte :"
    for r in range(4):
        row_in, row_out = "  IN: [", " OUT: ["
        for c in range(4):
            byte = state[r][c]
            new_byte = INV_S_BOX[byte]
            new_state[r][c] = new_byte
            row_in += f"{byte:02x} "
            row_out += f"{new_byte:02x} "
        desc += f"\n{row_in.strip()}] -> {row_out.strip()}]"
    trace_list.append(desc)
    return new_state


def inv_shift_rows(state: State, trace_list: list[str]) -> State:
    """InvShiftRows : décalage des lignes vers la droite (inverse de ShiftRows)."""
    new_state = [row[:] for row in state]
    desc = "Application de InvShiftRows :"
    desc += f"\n  Ligne 0 (pas de décalage): {new_state[0]}"
    new_state[1] = state[1][-1:] + state[1][:-1]
    desc += f"\n  Ligne 1 (décalage de 1 à droite): {new_state[1]}"
    new_state[2] = state[2][-2:] + state[2][:-2]
    desc += f"\n  Ligne 2 (décalage de 2 à droite): {new_state[2]}"
    new_state[3] = state[3][-3:] + state[3][:-3]
    desc += f"\n  Ligne 3 (décalage de 3 à droite): {new_state[3]}"
    trace_list.append(desc)
    return new_state


def inv_mix_single_column(column: list[int]) -> list[int]:
    """Multiplication par la matrice inverse de MixColumns (coefficients 0x0e,0x0b,0x0d,0x09)."""
    matrix = [
        [0x0E, 0x0B, 0x0D, 0x09],
        [0x09, 0x0E, 0x0B, 0x0D],
        [0x0D, 0x09, 0x0E, 0x0B],
        [0x0B, 0x0D, 0x09, 0x0E],
    ]
    new_col = [0] * 4
    for r in range(4):
        value = 0
        for c in range(4):
            value = gadd(value, gmul(matrix[r][c], column[c]))
        new_col[r] = value
    return new_col


def inv_mix_columns(state: State, trace_list: list[str]) -> State:
    """InvMixColumns : inverse de MixColumns, colonne par colonne."""
    new_state = [[0] * 4 for _ in range(4)]
    desc = "Application de InvMixColumns (matrice inverse GF(2^8) par colonne) :"
    for c in range(4):
        col_in = [state[r][c] for r in range(4)]
        col_out = inv_mix_single_column(col_in)
        desc += f"\n  Colonne {c}: {col_in} -> {col_out}"
        for r in range(4):
            new_state[r][c] = col_out[r]
    trace_list.append(desc)
    return new_state


# --- Simulateur par bloc brut (16 octets exacts, sans troncature ni bourrage
# implicite) : c'est le brique reutilisee par les fonctions multi-blocs. Le
# comportement de `simulate_aes_encrypt`/`text_to_state` ci-dessus (troncature
# silencieuse a 16 caracteres) reste inchange pour ne pas casser les tests
# existants ni le vecteur pedagogique historique.

def _bytes_to_state(data: bytes) -> State:
    state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = data[c * 4 + r]
    return state


def _state_to_bytes(state: State) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def encrypt_block(block: bytes, key_words: list[Word]) -> tuple[bytes, list[dict]]:
    """Chiffre un unique bloc de 16 octets, en tracant chaque round (AES-128)."""
    if len(block) != 16:
        raise ValueError("Un bloc AES fait exactement 16 octets.")

    steps = []
    round_keys, key_schedule_trace = expand_key(key_words)
    steps.extend(key_schedule_trace)

    state = _bytes_to_state(block)
    round_trace = []
    state = add_round_key(state, round_keys[0], round_trace)
    steps.append({"phase": "Chiffrement", "round": 0,
                  "description": "Round 0 (Pré-calcul):\n" + "\n".join(round_trace),
                  "state_hex": state_to_str(state)})

    for r in range(1, 10):
        round_trace = []
        state = sub_bytes(state, round_trace)
        state = shift_rows(state, round_trace)
        state = mix_columns(state, round_trace)
        state = add_round_key(state, round_keys[r], round_trace)
        steps.append({"phase": "Chiffrement", "round": r,
                      "description": f"--- Round {r} ---\n" + "\n\n".join(round_trace),
                      "state_hex": state_to_str(state)})

    round_trace = []
    state = sub_bytes(state, round_trace)
    state = shift_rows(state, round_trace)
    round_trace.append("MixColumns: [OMIS (Round Final)]")
    state = add_round_key(state, round_keys[10], round_trace)
    steps.append({"phase": "Chiffrement", "round": 10,
                  "description": "--- Round 10 (Final) ---\n" + "\n\n".join(round_trace),
                  "state_hex": state_to_str(state)})

    return _state_to_bytes(state), steps


def decrypt_block(block: bytes, key_words: list[Word]) -> tuple[bytes, list[dict]]:
    """
    Déchiffre un unique bloc de 16 octets : rounds appliqués dans l'ordre
    inverse (10 -> 0), chaque transformation remplacée par son inverse.
    """
    if len(block) != 16:
        raise ValueError("Un bloc AES fait exactement 16 octets.")

    steps = []
    round_keys, key_schedule_trace = expand_key(key_words)
    steps.extend(key_schedule_trace)

    state = _bytes_to_state(block)

    round_trace = []
    state = add_round_key(state, round_keys[10], round_trace)
    round_trace.append("InvMixColumns: [OMIS (dernier round de chiffrement)]")
    state = inv_shift_rows(state, round_trace)
    state = inv_sub_bytes(state, round_trace)
    steps.append({"phase": "Déchiffrement", "round": 10,
                  "description": "--- Round 10 (inverse) ---\n" + "\n\n".join(round_trace),
                  "state_hex": state_to_str(state)})

    for r in range(9, 0, -1):
        round_trace = []
        state = add_round_key(state, round_keys[r], round_trace)
        state = inv_mix_columns(state, round_trace)
        state = inv_shift_rows(state, round_trace)
        state = inv_sub_bytes(state, round_trace)
        steps.append({"phase": "Déchiffrement", "round": r,
                      "description": f"--- Round {r} (inverse) ---\n" + "\n\n".join(round_trace),
                      "state_hex": state_to_str(state)})

    round_trace = []
    state = add_round_key(state, round_keys[0], round_trace)
    steps.append({"phase": "Déchiffrement", "round": 0,
                  "description": "Round 0 (final, inverse) :\n" + "\n".join(round_trace),
                  "state_hex": state_to_str(state)})

    return _state_to_bytes(state), steps


# --- Simulation multi-blocs (chiffrement et déchiffrement pas à pas) ---------
# L'ancien simulateur ne traitait qu'un seul bloc de 16 caractères, tronquait
# silencieusement au-delà, et ne simulait que le chiffrement. Ici : bourrage
# PKCS#7 explicite et tracé, découpage en N blocs, et le déchiffrement complet
# (rounds inverses) est simulé lui aussi. Les blocs sont chaînés en ECB (le
# chaînage CBC/CTR est la responsabilité de `modes_tool`, qui montre
# précisément pourquoi ECB seul est un mauvais choix).

def simulate_aes_encrypt_multiblock(plain_text: str, key_str: str) -> dict:
    key_words, key_prep_trace = key_to_words(key_str)
    plain_bytes = plain_text.encode("utf-8")
    padded = pkcs7_pad(plain_bytes, 16)
    blocks = [padded[i:i + 16] for i in range(0, len(padded), 16)]

    steps = [{
        "step": 0,
        "phase": "Bourrage PKCS#7",
        "description": (
            f"Texte : '{plain_text}' ({len(plain_bytes)} octets).\n"
            f"Bourrage PKCS#7 jusqu'à un multiple de 16 octets : "
            f"{len(padded)} octets ajoutés = {padded[-1]}.\n"
            f"Découpage en {len(blocks)} bloc(s) de 16 octets."
        ),
        "block_count": len(blocks),
    }, {"step": 1, "phase": "Préparation de la clé", "description": key_prep_trace}]

    block_results = []
    cipher_bytes = b""
    for index, block in enumerate(blocks):
        cipher_block, block_steps = encrypt_block(block, key_words)
        cipher_bytes += cipher_block
        for s in block_steps:
            s["block"] = index
        steps.append({
            "step": len(steps),
            "phase": "Bloc",
            "block": index,
            "description": f"--- Bloc {index} ({block.hex()}) ---",
            "block_steps": block_steps,
            "block_result_hex": cipher_block.hex(),
        })
        block_results.append(cipher_block.hex())

    steps.append({
        "step": len(steps),
        "phase": "Final",
        "description": f"Fin du chiffrement. Résultat ({len(blocks)} bloc(s)) : {cipher_bytes.hex()}",
        "final_result_hex": cipher_bytes.hex(),
    })

    return {
        "final_result_hex": cipher_bytes.hex(),
        "block_count": len(blocks),
        "block_results": block_results,
        "steps": steps,
    }


def simulate_aes_decrypt_multiblock(cipher_hex: str, key_str: str) -> dict:
    key_words, key_prep_trace = key_to_words(key_str)
    cipher_bytes = bytes.fromhex(cipher_hex)
    if len(cipher_bytes) % 16 != 0:
        raise ValueError("Le chiffré doit être un multiple de 16 octets.")
    blocks = [cipher_bytes[i:i + 16] for i in range(0, len(cipher_bytes), 16)]

    steps = [{"step": 0, "phase": "Préparation de la clé", "description": key_prep_trace}]

    plain_padded = b""
    for index, block in enumerate(blocks):
        plain_block, block_steps = decrypt_block(block, key_words)
        plain_padded += plain_block
        for s in block_steps:
            s["block"] = index
        steps.append({
            "step": len(steps),
            "phase": "Bloc",
            "block": index,
            "description": f"--- Bloc {index} ({block.hex()}) ---",
            "block_steps": block_steps,
            "block_result_hex": plain_block.hex(),
        })

    try:
        plain_bytes = pkcs7_unpad(plain_padded, 16)
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
