"""
Tests du laboratoire d'attaque par oracle de bourrage PKCS#7 (Vaudenay, 2002).

Le vecteur officiel du registre verrouille `encrypt` contre une regression.
Ici : la propriete cryptographique elle-meme — l'attaque retrouve le clair
sans jamais lire la cle — sur plusieurs textes, tailles et le PKCS#7 nu.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from registry.errors import InvalidInput
from utils import padding_oracle

client = TestClient(app)

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
IV_HEX = "101112131415161718191a1b1c1d1e1f"


def unwrap(response) -> dict:
    body = response.json()
    assert body["ok"] is True, body
    return body["data"]


# --- PKCS#7 pur (sans chiffrement) -------------------------------------------

@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 33])
def test_pkcs7_pad_unpad_round_trip(length):
    data = bytes(range(length % 256)) if length else b""
    data = (data * (length // max(len(data), 1) + 1))[:length]
    padded = padding_oracle.pkcs7_pad(data)
    assert len(padded) % padding_oracle.BLOCK_SIZE == 0
    assert padding_oracle.pkcs7_unpad(padded) == data


def test_pkcs7_unpad_rejects_bad_padding():
    with pytest.raises(InvalidInput):
        padding_oracle.pkcs7_unpad(b"\x00" * 15 + b"\x05")  # dernier octet 5, mais pas 5 octets identiques


def test_pkcs7_unpad_rejects_zero_length_padding():
    with pytest.raises(InvalidInput):
        padding_oracle.pkcs7_unpad(b"\x00" * 16)


# --- L'attaque elle-meme : jamais la cle, seulement l'oracle -----------------

@pytest.mark.parametrize("plaintext", [
    "A",
    "Exactement seize!",
    "Un message qui traverse plusieurs blocs de seize octets chacun",
    "",
])
def test_attack_recovers_plaintext_without_the_key(plaintext):
    enc = padding_oracle.encrypt_for_oracle(KEY_HEX, IV_HEX, plaintext)
    result = padding_oracle.padding_oracle_attack(KEY_HEX, IV_HEX, enc["cipher_hex"])
    assert result["plain"] == plaintext


def test_attack_through_the_api():
    enc = unwrap(client.post("/api/modern/paddingoracle/encrypt", json={
        "key_hex": KEY_HEX, "iv_hex": IV_HEX, "plaintext": "Casse sans la cle",
    }))
    result = unwrap(client.post("/api/modern/paddingoracle/attack", json={
        "key_hex": KEY_HEX, "iv_hex": IV_HEX, "cipher_hex": enc["cipher_hex"],
    }))
    assert result["plain"] == "Casse sans la cle"


def test_oracle_query_reports_validity():
    enc = padding_oracle.encrypt_for_oracle(KEY_HEX, IV_HEX, "test")
    valid = padding_oracle.oracle_query(KEY_HEX, IV_HEX, enc["cipher_hex"])
    assert valid["padding_valid"] is True

    tampered = bytearray(bytes.fromhex(enc["cipher_hex"]))
    tampered[-1] ^= 0xFF
    invalid = padding_oracle.oracle_query(KEY_HEX, IV_HEX, tampered.hex())
    assert invalid["padding_valid"] is False


def test_official_vector_matches_registry():
    """Le meme vecteur que celui verrouille dans registry/catalog/symmetric.py."""
    result = padding_oracle.encrypt_for_oracle(KEY_HEX, IV_HEX, "Attaque")
    assert result == {"cipher_hex": "b4e262df6ef2d4d08dc50af8c4d9aed3", "block_count": 1}
