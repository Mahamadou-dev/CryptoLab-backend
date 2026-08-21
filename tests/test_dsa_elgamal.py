"""
DSA (signature, couche production) et ElGamal (chiffrement, petits nombres
pedagogiques) — fin du Sprint 6 : clef publique.
"""

from __future__ import annotations

import pytest

from registry.errors import InvalidInput
from utils import dsa_tool, elgamal_tool

# --- DSA -----------------------------------------------------------------

def test_dsa_sign_verify_round_trip():
    keys = dsa_tool.generate_dsa_keys()
    signed = dsa_tool.sign_dsa("Bonjour CryptoLab", keys["private_key"])
    result = dsa_tool.verify_dsa("Bonjour CryptoLab", signed["signature_hex"], keys["public_key"])
    assert result["valid"] is True


def test_dsa_verify_rejects_altered_message():
    keys = dsa_tool.generate_dsa_keys()
    signed = dsa_tool.sign_dsa("Bonjour CryptoLab", keys["private_key"])
    result = dsa_tool.verify_dsa("Bonjour cryptolab", signed["signature_hex"], keys["public_key"])
    assert result["valid"] is False


def test_dsa_verify_rejects_altered_signature():
    keys = dsa_tool.generate_dsa_keys()
    signed = dsa_tool.sign_dsa("Bonjour CryptoLab", keys["private_key"])
    tampered = format(int(signed["signature_hex"], 16) ^ 1, "x").zfill(len(signed["signature_hex"]))
    result = dsa_tool.verify_dsa("Bonjour CryptoLab", tampered, keys["public_key"])
    assert result["valid"] is False


def test_dsa_signatures_differ_each_time_probabilistic():
    keys = dsa_tool.generate_dsa_keys()
    sig1 = dsa_tool.sign_dsa("meme message", keys["private_key"])["signature_hex"]
    sig2 = dsa_tool.sign_dsa("meme message", keys["private_key"])["signature_hex"]
    assert sig1 != sig2


def test_dsa_sign_rejects_non_dsa_key():
    from registry.errors import InvalidKey

    with pytest.raises(InvalidKey):
        dsa_tool.sign_dsa("x", "not a pem key")


# --- ElGamal ---------------------------------------------------------------

def test_elgamal_keygen_vector():
    # p=23, g=5 (meme groupe que le vecteur Diffie-Hellman textbook)
    result = elgamal_tool.elgamal_keygen(p=23, g=5, x=6)
    assert result == {"p": 23, "g": 5, "x": 6, "y": 8}


def test_elgamal_encrypt_vector():
    result = elgamal_tool.elgamal_encrypt(p=23, g=5, y=8, m=10, k=3)
    assert result["c1"] == 10
    assert result["c2"] == 14


def test_elgamal_decrypt_vector_round_trip():
    result = elgamal_tool.elgamal_decrypt(p=23, x=6, c1=10, c2=14)
    assert result["m"] == 10


def test_elgamal_full_round_trip_random_k():
    keys = elgamal_tool.elgamal_keygen(p=23, g=5, x=6)
    enc = elgamal_tool.elgamal_encrypt(p=23, g=5, y=keys["y"], m=15)
    dec = elgamal_tool.elgamal_decrypt(p=23, x=6, c1=enc["c1"], c2=enc["c2"])
    assert dec["m"] == 15


def test_elgamal_rejects_message_out_of_range():
    with pytest.raises(InvalidInput):
        elgamal_tool.elgamal_encrypt(p=23, g=5, y=8, m=23, k=3)


def test_elgamal_rejects_small_p():
    with pytest.raises(InvalidInput):
        elgamal_tool.elgamal_keygen(p=3, g=2, x=1)
