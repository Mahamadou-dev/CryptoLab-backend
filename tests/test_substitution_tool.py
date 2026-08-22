import pytest

from registry.errors import InvalidKey
from utils import substitution_tool


def test_rot13_is_involutive():
    text = "The Quick Brown Fox, 42!"
    once = substitution_tool.rot13(text)
    twice = substitution_tool.rot13(once)
    assert once != text
    assert twice == text


def test_rot13_known_vector():
    assert substitution_tool.rot13("Why did the chicken cross the road?") == (
        "Jul qvq gur puvpxra pebff gur ebnq?"
    )


def test_atbash_is_involutive():
    text = "Attack at Dawn!"
    once = substitution_tool.atbash(text)
    twice = substitution_tool.atbash(once)
    assert once != text
    assert twice == text


def test_atbash_known_vector():
    assert substitution_tool.atbash("ATTACK AT DAWN") == "ZGGZXP ZG WZDM"


def test_substitution_round_trip():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    cipher = substitution_tool.substitution_encrypt("Hello, World!", key)
    assert cipher != "Hello, World!"
    assert substitution_tool.substitution_decrypt(cipher, key) == "Hello, World!"


def test_substitution_preserves_case_and_non_letters():
    key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"  # Atbash exprime comme cle generale
    cipher = substitution_tool.substitution_encrypt("Hi, Bob! 42", key)
    assert cipher == substitution_tool.atbash("Hi, Bob! 42")


@pytest.mark.parametrize(
    "bad_key",
    [
        "TROPCOURT",
        "AAAAAAAAAAAAAAAAAAAAAAAAAA",  # 26 caracteres mais pas une permutation
        "QWERTYUIOPASDFGHJKLZXCVBN1",  # un chiffre a la place d'une lettre
    ],
)
def test_invalid_key_is_rejected(bad_key):
    with pytest.raises(InvalidKey):
        substitution_tool.substitution_encrypt("HELLO", bad_key)
