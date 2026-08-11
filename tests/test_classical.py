"""
Chiffres classiques : vecteurs de reference et proprietes d'aller-retour.

Les vecteurs proviennent des exemples canoniques que l'on retrouve dans la
litterature (Wikipedia, Kahn, cours universitaires standard).
"""

import pytest

from utils import caesar, columnar, playfair, rail_fence, vigenere

ROUND_TRIP_SAMPLES = [
    "ATTACKATDAWN",
    "Attack at dawn!",
    "Le chiffre de Cesar, 44 av. J.-C.",
    "a",
    "",
]


# --- Cesar -------------------------------------------------------------------

@pytest.mark.parametrize(
    "plain, shift, expected",
    [
        ("BONJOUR", 3, "ERQMRXU"),
        ("ATTACKATDAWN", 3, "DWWDFNDWGDZQ"),
        ("HELLO, WORLD!", 3, "KHOOR, ZRUOG!"),  # ponctuation conservee
        ("XYZ", 3, "ABC"),                       # bouclage de l'alphabet
        ("MiXeD", 13, "ZvKrQ"),                  # casse preservee
    ],
)
def test_caesar_vectors(plain, shift, expected):
    assert caesar.caesar_encrypt(plain, shift) == expected


@pytest.mark.parametrize("text", ROUND_TRIP_SAMPLES)
@pytest.mark.parametrize("shift", [1, 3, 13, 25])
def test_caesar_round_trip(text, shift):
    assert caesar.caesar_decrypt(caesar.caesar_encrypt(text, shift), shift) == text


def test_caesar_shift_26_is_identity():
    assert caesar.caesar_encrypt("IDENTITE", 26) == "IDENTITE"


# --- Vigenere ----------------------------------------------------------------

@pytest.mark.parametrize(
    "plain, key, expected",
    [
        # Vecteur canonique : ATTACKATDAWN / LEMON -> LXFOPVEFRNHR
        ("ATTACKATDAWN", "LEMON", "LXFOPVEFRNHR"),
        ("attackatdawn", "lemon", "lxfopvefrnhr"),
    ],
)
def test_vigenere_vectors(plain, key, expected):
    assert vigenere.vigenere_encrypt(plain, key) == expected


@pytest.mark.parametrize("text", ROUND_TRIP_SAMPLES)
def test_vigenere_round_trip(text):
    assert vigenere.vigenere_decrypt(vigenere.vigenere_encrypt(text, "CRYPTO"), "CRYPTO") == text


def test_vigenere_key_a_is_identity():
    assert vigenere.vigenere_encrypt("IDENTITE", "A") == "IDENTITE"


# --- Playfair ----------------------------------------------------------------

def test_playfair_matrix_is_5x5_without_j():
    matrix = playfair.generate_playfair_matrix("PLAYFAIR EXAMPLE")
    assert len(matrix) == 5
    assert all(len(row) == 5 for row in matrix)

    flat = [c for row in matrix for c in row]
    assert len(set(flat)) == 25
    assert "J" not in flat


def test_playfair_canonical_vector():
    """Vecteur de reference : cle PLAYFAIR EXAMPLE."""
    cipher = playfair.playfair_encrypt("HIDE THE GOLD IN THE TREE STUMP", "PLAYFAIREXAMPLE")
    assert cipher == "BMODZBXDNABEKUDMUIXMMOUVIF"


def test_playfair_round_trip_removes_padding():
    """
    Regression : le dechiffrement rendait 'HELXLO WORLDX' au lieu de 'HELLOWORLD'.
    """
    cipher = playfair.playfair_encrypt("HELLO WORLD", "MONARCHY")
    assert playfair.playfair_decrypt(cipher, "MONARCHY") == "HELLOWORLD"


def test_playfair_raw_output_keeps_padding():
    cipher = playfair.playfair_encrypt("HELLO WORLD", "MONARCHY")
    raw = playfair.playfair_decrypt(cipher, "MONARCHY", remove_padding=False)
    assert raw == "HELXLOWORLDX"


def test_playfair_digrams_span_whole_message():
    """
    Regression : les digrammes etaient formes mot par mot, si bien que 'A B'
    produisait deux digrammes bourres ('AX', 'BX') au lieu d'un seul ('AB').
    """
    assert playfair.build_digrams("A B") == ["AB"]
    assert playfair.build_digrams("HELLO WORLD") == ["HE", "LX", "LO", "WO", "RL", "DX"]


def test_playfair_doubled_x_uses_alternate_filler():
    """Un doublon de X ne peut pas etre separe par un X."""
    assert playfair.build_digrams("XX") == ["XQ", "XQ"]


def test_playfair_merges_i_and_j():
    assert playfair.playfair_encrypt("JAM", "MONARCHY") == playfair.playfair_encrypt("IAM", "MONARCHY")


# --- Rail Fence (zigzag) -----------------------------------------------------

def test_rail_fence_canonical_vector():
    """
    Le motif zigzag classique sur 3 rails.

        W . . . E . . . C . . . R . .
        . E . R . D . S . O . E . E .
        . . A . . . I . . . V . . . D
    """
    assert rail_fence.rail_fence_encrypt("WEAREDISCOVERED", 3) == "WECRERDSOEEAIVD"


def test_rail_fence_two_rails():
    assert rail_fence.rail_fence_encrypt("ABCDEF", 2) == "ACEBDF"


@pytest.mark.parametrize("text", ROUND_TRIP_SAMPLES)
@pytest.mark.parametrize("rails", [2, 3, 4, 7])
def test_rail_fence_round_trip(text, rails):
    cipher = rail_fence.rail_fence_encrypt(text, rails)
    assert rail_fence.rail_fence_decrypt(cipher, rails) == text


def test_rail_fence_preserves_length_and_characters():
    """
    Regression : l'ancienne version supprimait les espaces et ajoutait des 'X'
    de bourrage qui n'etaient jamais retires.
    """
    text = "WE ARE DISCOVERED. FLEE AT ONCE!"
    cipher = rail_fence.rail_fence_encrypt(text, 4)
    assert len(cipher) == len(text)
    assert sorted(cipher) == sorted(text)
    assert rail_fence.rail_fence_decrypt(cipher, 4) == text


def test_rail_fence_single_rail_is_identity():
    assert rail_fence.rail_fence_encrypt("IDENTITE", 1) == "IDENTITE"


def test_rail_fence_grid_shape():
    grid = rail_fence.rail_fence_grid("WEAREDISCOVERED", 3)
    assert len(grid) == 3
    assert grid[0][0] == "W"
    assert grid[1][1] == "E"
    assert grid[2][2] == "A"
    assert grid[0][1] == ""  # case vide du zigzag


# --- Transposition par colonnes ----------------------------------------------

def test_columnar_key_order():
    # ZEBRAS : A vient en premier (colonne 4), puis B (2), E (1), R (3), S (5), Z (0)
    assert columnar.key_order("ZEBRAS") == [4, 2, 1, 3, 5, 0]


def test_columnar_canonical_vector():
    """Vecteur de reference : ZEBRAS / WEAREDISCOVEREDFLEEATONCE."""
    cipher = columnar.columnar_encrypt("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS")
    assert cipher == "EVLNACDTESEAROFODEECWIREE"


@pytest.mark.parametrize("text", ROUND_TRIP_SAMPLES)
@pytest.mark.parametrize("key", ["ZEBRAS", "CRYPTO", "AB"])
def test_columnar_round_trip(text, key):
    assert columnar.columnar_decrypt(columnar.columnar_encrypt(text, key), key) == text


def test_columnar_adds_no_padding():
    text = "WE ARE DISCOVERED"
    cipher = columnar.columnar_encrypt(text, "ZEBRAS")
    assert len(cipher) == len(text)
    assert sorted(cipher) == sorted(text)


def test_columnar_rejects_empty_key():
    with pytest.raises(ValueError):
        columnar.columnar_encrypt("TEXTE", "   ")


def test_columnar_handles_repeated_key_letters():
    """Les lettres identiques sont departagees par leur position (tri stable)."""
    assert columnar.key_order("AAB") == [0, 1, 2]
    assert columnar.columnar_decrypt(columnar.columnar_encrypt("HELLOWORLD", "AAB"), "AAB") == "HELLOWORLD"
