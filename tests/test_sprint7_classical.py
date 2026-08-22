import pytest

from registry.errors import InvalidInput, InvalidKey
from utils import affine_tool, enigma_tool, frequency_tool, hill_tool, otp_tool

# --- Affine --------------------------------------------------------------

def test_affine_known_vector():
    assert affine_tool.affine_encrypt("AFFINE CIPHER", 5, 8) == "IHHWVC SWFRCP"
    assert affine_tool.affine_decrypt("IHHWVC SWFRCP", 5, 8) == "AFFINE CIPHER"


def test_affine_round_trip_preserves_non_letters():
    cipher = affine_tool.affine_encrypt("Hi, Bob! 42", 7, 3)
    assert affine_tool.affine_decrypt(cipher, 7, 3) == "Hi, Bob! 42"


def test_affine_rejects_non_invertible_a():
    with pytest.raises(InvalidKey):
        affine_tool.affine_encrypt("HELLO", 2, 3)  # gcd(2, 26) = 2


# --- Hill ------------------------------------------------------------------

def test_hill_known_vector():
    assert hill_tool.hill_encrypt("HELP", 3, 3, 2, 5) == "HIAT"
    assert hill_tool.hill_decrypt("HIAT", 3, 3, 2, 5) == "HELP"


def test_hill_rejects_singular_matrix():
    with pytest.raises(InvalidKey):
        hill_tool.hill_encrypt("HELP", 2, 4, 1, 2)  # determinant 0


def test_hill_rejects_odd_length_ciphertext():
    with pytest.raises(InvalidInput):
        hill_tool.hill_decrypt("HIA", 3, 3, 2, 5)


# --- One-Time Pad ------------------------------------------------------------

def test_otp_known_vector():
    assert otp_tool.otp_encrypt("HELLO", "XMCKL") == "EQNVZ"
    assert otp_tool.otp_decrypt("EQNVZ", "XMCKL") == "HELLO"


def test_otp_rejects_key_shorter_than_message():
    with pytest.raises(InvalidKey):
        otp_tool.otp_encrypt("HELLOWORLD", "SHORT")


# --- Analyse de frequence ---------------------------------------------------

def test_frequency_analysis_known_text():
    result = frequency_tool.analyze("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
    assert result["letter_count"] == 35
    assert result["index_of_coincidence"] == pytest.approx(0.0218, abs=1e-4)
    assert result["frequencies"]["O"] == 4


def test_index_of_coincidence_uniform_beats_natural_language_far_from_both():
    # Un texte d'une seule lettre repetee a un IC de 1.0 : maximalement inegal.
    assert frequency_tool.index_of_coincidence("AAAA") == pytest.approx(1.0)


# --- Enigma ------------------------------------------------------------------

def test_enigma_known_vector():
    out = enigma_tool.enigma_encrypt("AAAAA", ["I", "II", "III"], "AAA")
    assert out["result"] == "BDZGO"
    assert len(out["steps"]) == 5


def test_enigma_is_self_reciprocal_with_plugboard():
    message = "HELLOWORLD"
    encrypted = enigma_tool.enigma_encrypt(
        message, ["I", "II", "III"], "AAA", plugboard="AB CD"
    )["result"]
    assert encrypted != message
    decrypted = enigma_tool.enigma_encrypt(
        encrypted, ["I", "II", "III"], "AAA", plugboard="AB CD"
    )["result"]
    assert decrypted == message


def test_enigma_never_maps_a_letter_to_itself():
    out = enigma_tool.enigma_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", ["III", "II", "I"], "QWE")
    for plain, cipher in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", out["result"], strict=True):
        assert plain != cipher


def test_enigma_rejects_duplicate_rotors():
    with pytest.raises(InvalidInput):
        enigma_tool.enigma_encrypt("A", ["I", "I", "III"], "AAA")


def test_enigma_rejects_malformed_plugboard():
    with pytest.raises(InvalidInput):
        enigma_tool.enigma_encrypt("A", ["I", "II", "III"], "AAA", plugboard="ABC")


def test_enigma_rejects_letter_in_two_plugboard_pairs():
    with pytest.raises(InvalidInput):
        enigma_tool.enigma_encrypt("A", ["I", "II", "III"], "AAA", plugboard="AB AC")
