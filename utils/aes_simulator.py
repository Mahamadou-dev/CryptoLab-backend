from . import aes_constants as const
from .aes_math import mix_single_column, gadd
from typing import List, Dict, Any

# --- Types de données ---
# Un "mot" (word) est une liste de 4 bytes [b0, b1, b2, b3]
Word = List[int]
# Un "état" (state) est une matrice 4x4 de bytes
State = List[List[int]]


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


def key_to_words(key: str) -> (List[Word], str):
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


def words_to_str(words: List[Word]) -> str:
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
    return [gadd(b1, b2) for b1, b2 in zip(w1, w2)]


# --- Opérations des Rounds AES ---

def sub_bytes(state: State, trace_list: List[str]) -> State:
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


def shift_rows(state: State, trace_list: List[str]) -> State:
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


def mix_columns(state: State, trace_list: List[str]) -> State:
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


def add_round_key(state: State, round_key: State, trace_list: List[str]) -> State:
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

def expand_key(key_words: List[Word]) -> (List[State], List[Dict]):
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
        state_start = state

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
        "description": f"--- Round 10 (Final) ---\n" + "\n\n".join(round_trace),
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