"""
Tests ECDSA (secp256k1) et Ed25519 (RFC 8032).

Aucun vecteur officiel a valeur fixe (clefs generees aleatoirement pour
`generate-keys`, ECDSA probabiliste par construction). La propriete verifiee
est signer -> verifier -> valide, signer deux fois -> memes octets (Ed25519
seulement, deterministe) ou octets differents (ECDSA, nonce aleatoire), et
message altere -> invalide.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from registry.errors import InvalidInput
from utils import signature_tool

client = TestClient(app)


def unwrap(response) -> dict:
    body = response.json()
    assert body["ok"] is True, body
    return body["data"]


# --- ECDSA / secp256k1 -------------------------------------------------------

@pytest.fixture(scope="module")
def ecdsa_keys():
    return signature_tool.generate_ecdsa_keys()


def test_ecdsa_sign_and_verify(ecdsa_keys):
    signed = signature_tool.sign_ecdsa("bonjour", ecdsa_keys["private_key"])
    result = signature_tool.verify_ecdsa("bonjour", signed["signature_hex"], ecdsa_keys["public_key"])
    assert result["valid"] is True


def test_ecdsa_is_probabilistic(ecdsa_keys):
    s1 = signature_tool.sign_ecdsa("meme message", ecdsa_keys["private_key"])
    s2 = signature_tool.sign_ecdsa("meme message", ecdsa_keys["private_key"])
    assert s1["signature_hex"] != s2["signature_hex"]


def test_ecdsa_rejects_tampered_message(ecdsa_keys):
    signed = signature_tool.sign_ecdsa("original", ecdsa_keys["private_key"])
    result = signature_tool.verify_ecdsa("altere", signed["signature_hex"], ecdsa_keys["public_key"])
    assert result["valid"] is False


def test_ecdsa_through_the_api():
    keys = unwrap(client.get("/api/asymmetric/ecdsa/generate-keys"))
    signed = unwrap(client.post("/api/asymmetric/ecdsa/sign", json={
        "message": "via l'API", "private_key": keys["private_key"],
    }))
    verified = unwrap(client.post("/api/asymmetric/ecdsa/verify", json={
        "message": "via l'API", "signature_hex": signed["signature_hex"], "public_key": keys["public_key"],
    }))
    assert verified["valid"] is True


# --- Ed25519 ------------------------------------------------------------------

@pytest.fixture(scope="module")
def ed25519_keys():
    return signature_tool.generate_ed25519_keys()


def test_ed25519_sign_and_verify(ed25519_keys):
    message_hex = "48656c6c6f"  # "Hello" en hexadecimal
    signed = signature_tool.sign_ed25519(message_hex, ed25519_keys["private_hex"])
    result = signature_tool.verify_ed25519(message_hex, signed["signature_hex"], ed25519_keys["public_hex"])
    assert result["valid"] is True


def test_ed25519_is_deterministic(ed25519_keys):
    s1 = signature_tool.sign_ed25519("deadbeef", ed25519_keys["private_hex"])
    s2 = signature_tool.sign_ed25519("deadbeef", ed25519_keys["private_hex"])
    assert s1["signature_hex"] == s2["signature_hex"]


def test_ed25519_rejects_tampered_message(ed25519_keys):
    signed = signature_tool.sign_ed25519("aa", ed25519_keys["private_hex"])
    result = signature_tool.verify_ed25519("bb", signed["signature_hex"], ed25519_keys["public_hex"])
    assert result["valid"] is False


def test_ed25519_rejects_wrong_key_length():
    with pytest.raises(InvalidInput):
        signature_tool.sign_ed25519("aa", "00")


def test_ed25519_through_the_api():
    keys = unwrap(client.get("/api/asymmetric/ed25519/generate-keys"))
    signed = unwrap(client.post("/api/asymmetric/ed25519/sign", json={
        "message_hex": "deadbeef", "private_hex": keys["private_hex"],
    }))
    verified = unwrap(client.post("/api/asymmetric/ed25519/verify", json={
        "message_hex": "deadbeef", "signature_hex": signed["signature_hex"], "public_hex": keys["public_hex"],
    }))
    assert verified["valid"] is True
