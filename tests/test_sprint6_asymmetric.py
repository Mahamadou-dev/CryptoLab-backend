"""
Sprint 6 — clef publique : RSA petits nombres, signatures RSA, Diffie-Hellman,
ECDH (X25519) et addition de points sur secp256k1.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from registry.errors import InvalidInput
from utils import dh_tool, ecc_tool, rsa_signature_tool, rsa_small

client = TestClient(app)


def unwrap(response) -> dict:
    body = response.json()
    assert body["ok"] is True, body
    return body["data"]


# --- RSA petits nombres --------------------------------------------------------

def test_small_rsa_keygen_matches_textbook_example():
    keys = rsa_small.generate_small_rsa(61, 53, 17)
    assert (keys.n, keys.phi, keys.e, keys.d) == (3233, 3120, 17, 2753)


def test_small_rsa_encrypt_decrypt_roundtrip_matches_textbook_example():
    keys = rsa_small.generate_small_rsa(61, 53, 17)
    enc = rsa_small.encrypt_small_rsa(65, keys.e, keys.n)
    assert enc["cipher"] == 2790
    dec = rsa_small.decrypt_small_rsa(enc["cipher"], keys.d, keys.n)
    assert dec["plain"] == 65


def test_small_rsa_sign_and_verify():
    keys = rsa_small.generate_small_rsa(61, 53, 17)
    signed = rsa_small.sign_small_rsa(42, keys.d, keys.n)
    verified = rsa_small.verify_small_rsa(42, signed["signature"], keys.e, keys.n)
    assert verified["valid"] is True

    forged = rsa_small.verify_small_rsa(43, signed["signature"], keys.e, keys.n)
    assert forged["valid"] is False


def test_small_rsa_rejects_non_prime_inputs():
    with pytest.raises(InvalidInput):
        rsa_small.generate_small_rsa(4, 53)  # 4 n'est pas premier


def test_small_rsa_rejects_e_not_coprime_with_phi():
    with pytest.raises(InvalidInput):
        rsa_small.generate_small_rsa(61, 53, e=3120)  # e == phi(n)


def test_small_rsa_through_the_api():
    keygen = unwrap(client.post("/api/asymmetric/rsasmall/generate-keys", json={"p": 61, "q": 53, "e": 17}))
    assert keygen["n"] == 3233 and keygen["d"] == 2753

    enc = unwrap(client.post("/api/asymmetric/rsasmall/encrypt", json={"message": 65, "e": 17, "n": 3233}))
    assert enc["cipher"] == 2790

    dec = unwrap(client.post("/api/asymmetric/rsasmall/decrypt", json={"cipher": 2790, "d": 2753, "n": 3233}))
    assert dec["plain"] == 65


# --- Signature RSA (production) ------------------------------------------------

@pytest.fixture(scope="module")
def rsa_signing_keys():
    return rsa_signature_tool.generate_rsa_signing_keys()


def test_rsa_pkcs1v15_sign_and_verify(rsa_signing_keys):
    signature = rsa_signature_tool.sign_rsa_pkcs1v15("bonjour le monde", rsa_signing_keys["private_key"])
    result = rsa_signature_tool.verify_rsa_pkcs1v15(
        "bonjour le monde", signature["signature_hex"], rsa_signing_keys["public_key"]
    )
    assert result["valid"] is True


def test_rsa_pkcs1v15_is_deterministic(rsa_signing_keys):
    s1 = rsa_signature_tool.sign_rsa_pkcs1v15("meme message", rsa_signing_keys["private_key"])
    s2 = rsa_signature_tool.sign_rsa_pkcs1v15("meme message", rsa_signing_keys["private_key"])
    assert s1["signature_hex"] == s2["signature_hex"]


def test_rsa_pss_sign_and_verify(rsa_signing_keys):
    signature = rsa_signature_tool.sign_rsa_pss("bonjour le monde", rsa_signing_keys["private_key"])
    result = rsa_signature_tool.verify_rsa_pss(
        "bonjour le monde", signature["signature_hex"], rsa_signing_keys["public_key"]
    )
    assert result["valid"] is True


def test_rsa_pss_is_probabilistic(rsa_signing_keys):
    # Le sel aleatoire de PSS garantit que deux signatures du meme message
    # different presque toujours — contrairement a PKCS#1 v1.5.
    s1 = rsa_signature_tool.sign_rsa_pss("meme message", rsa_signing_keys["private_key"])
    s2 = rsa_signature_tool.sign_rsa_pss("meme message", rsa_signing_keys["private_key"])
    assert s1["signature_hex"] != s2["signature_hex"]


def test_rsa_signature_rejects_tampered_message(rsa_signing_keys):
    signature = rsa_signature_tool.sign_rsa_pkcs1v15("original", rsa_signing_keys["private_key"])
    result = rsa_signature_tool.verify_rsa_pkcs1v15(
        "altere", signature["signature_hex"], rsa_signing_keys["public_key"]
    )
    assert result["valid"] is False


def test_rsa_signature_through_the_api():
    keys = unwrap(client.get("/api/asymmetric/rsasignature/generate-keys"))
    signed = unwrap(
        client.post(
            "/api/asymmetric/rsasignature/sign-pss",
            json={"message": "via l'API", "private_key": keys["private_key"]},
        )
    )
    verified = unwrap(
        client.post(
            "/api/asymmetric/rsasignature/verify-pss",
            json={
                "message": "via l'API",
                "signature_hex": signed["signature_hex"],
                "public_key": keys["public_key"],
            },
        )
    )
    assert verified["valid"] is True


# --- Diffie-Hellman -------------------------------------------------------------

def test_dh_small_numbers_matches_textbook_example():
    result = dh_tool.dh_small_numbers(p=23, g=5, a=6, b=15)
    assert result["public_a"] == 8
    assert result["public_b"] == 19
    assert result["shared_secret"] == 2
    assert result["secrets_match"] is True


def test_dh_small_numbers_eve_never_sees_the_secrets():
    result = dh_tool.dh_small_numbers(p=23, g=5, a=6, b=15)
    assert "a" not in result["eve_sees"]
    assert "b" not in result["eve_sees"]
    assert "shared_secret" not in result["eve_sees"]


def test_dh_small_numbers_rejects_small_modulus():
    with pytest.raises(InvalidInput):
        dh_tool.dh_small_numbers(p=3, g=2, a=1, b=1)


def test_dh_through_the_api():
    result = unwrap(
        client.post("/api/asymmetric/diffiehellman/exchange", json={"p": 23, "g": 5, "a": 6, "b": 15})
    )
    assert result["shared_secret"] == 2


# --- ECDH (X25519) --------------------------------------------------------------

def test_ecdh_x25519_fixed_vector():
    result = dh_tool.ecdh_x25519_exchange(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
    )
    assert result["shared_secret_hex"] == "4274a32e953acb8314d0f09bcbcb5193c5ef799ddcd0036f8c4682e5801dac73"


def test_ecdh_x25519_roundtrip_alice_bob():
    alice = dh_tool.ecdh_x25519_generate()
    bob = dh_tool.ecdh_x25519_generate()

    shared_alice = dh_tool.ecdh_x25519_exchange(alice["private_hex"], bob["public_hex"])
    shared_bob = dh_tool.ecdh_x25519_exchange(bob["private_hex"], alice["public_hex"])

    assert shared_alice["shared_secret_hex"] == shared_bob["shared_secret_hex"]


def test_ecdh_rejects_wrong_length_keys():
    with pytest.raises(InvalidInput):
        dh_tool.ecdh_x25519_exchange("00", "00" * 32)


# --- ECC (secp256k1) -------------------------------------------------------------

def test_ecc_double_generator_matches_known_point():
    gx, gy = ecc_tool.SECP256K1_GX, ecc_tool.SECP256K1_GY
    result = ecc_tool.secp256k1_scalar_multiply(2, gx, gy)
    assert result["result"]["x"] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    assert result["result"]["y"] == 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A


def test_ecc_point_add_generator_to_itself_equals_double():
    gx, gy = ecc_tool.SECP256K1_GX, ecc_tool.SECP256K1_GY
    added = ecc_tool.secp256k1_point_add(gx, gy, gx, gy)
    doubled = ecc_tool.secp256k1_scalar_multiply(2, gx, gy)
    assert added["result"] == doubled["result"]


def test_ecc_scalar_multiply_by_group_order_returns_infinity():
    gx, gy = ecc_tool.SECP256K1_GX, ecc_tool.SECP256K1_GY
    # n*G = point a l'infini : n est l'ordre du groupe engendre par G.
    result = ecc_tool.scalar_multiply(ecc_tool.SECP256K1, ecc_tool.SECP256K1_N, (gx, gy))
    assert result is None


def test_ecc_rejects_point_not_on_curve():
    with pytest.raises(InvalidInput):
        ecc_tool.secp256k1_point_add(1, 1, ecc_tool.SECP256K1_GX, ecc_tool.SECP256K1_GY)


def test_ecc_through_the_api():
    gx, gy = ecc_tool.SECP256K1_GX, ecc_tool.SECP256K1_GY
    result = unwrap(
        client.post("/api/asymmetric/ecc/scalar-multiply", json={"k": 2, "x": gx, "y": gy})
    )
    assert result["result"]["x"] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
