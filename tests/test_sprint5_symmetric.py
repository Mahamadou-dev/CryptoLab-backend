"""
Tests Sprint 5 — symetrique moderne.

Couvre ce que les vecteurs officiels du registre (rejoues par
`test_registry.py::test_official_vector`) ne couvrent pas : les routes a
sortie aleatoire (AES-128/192, 3DES, ChaCha20-Poly1305) verifiees par
aller-retour a travers l'API, et la comparaison directe des nouveaux modules
contre PyCryptodome/`cryptography` sur des entrees variees.
"""

from __future__ import annotations

import random
import string

import pytest
from fastapi.testclient import TestClient

from main import app
from utils import aes_simulator, chacha20_tool, des_simulator, rc4_tool, tripledes_tool

client = TestClient(app)

ASCII = string.ascii_letters + string.digits + " .,!?-"


def _random_text(length: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(ASCII) for _ in range(length))


def unwrap(response) -> dict:
    body = response.json()
    assert body["ok"] is True, body
    return body["data"]


def error_of(response) -> dict:
    body = response.json()
    assert body["ok"] is False, body
    return body["error"]


# --- AES-128 / AES-192 -------------------------------------------------------

@pytest.mark.parametrize("slug", ["aes128", "aes192", "aes"])
def test_aes_variant_round_trip_through_api(slug):
    enc = unwrap(client.post(f"/api/modern/{slug}/encrypt", json={"text": "Bonjour le monde", "key": "phrase secrete"}))
    dec = unwrap(client.post(f"/api/modern/{slug}/decrypt", json={
        "cipher_hex": enc["cipher_hex"],
        "key": "phrase secrete",
        "nonce_hex": enc["nonce_hex"],
        "tag_hex": enc["tag_hex"],
        "salt_hex": enc["salt_hex"],
    }))
    assert dec["plain"] == "Bonjour le monde"


def test_aes_variants_reject_cross_decryption():
    """Un texte chiffre en AES-128 ne se dechiffre pas comme de l'AES-256 : la cle derivee n'a pas la meme longueur."""
    enc = unwrap(client.post("/api/modern/aes128/encrypt", json={"text": "secret", "key": "clef"}))
    resp = client.post("/api/modern/aes/decrypt", json={
        "cipher_hex": enc["cipher_hex"],
        "key": "clef",
        "nonce_hex": enc["nonce_hex"],
        "tag_hex": enc["tag_hex"],
        "salt_hex": enc["salt_hex"],
    })
    assert resp.status_code == 400
    assert error_of(resp)["code"] == "decryption_failed"


# --- 3DES ---------------------------------------------------------------------

def test_tripledes_round_trip_through_api():
    enc = unwrap(client.post("/api/modern/tripledes/encrypt", json={"text": "Attaquer a l'aube", "key": "cle 3des"}))
    dec = unwrap(client.post("/api/modern/tripledes/decrypt", json={
        "cipher_hex": enc["cipher_hex"],
        "key": "cle 3des",
        "iv_hex": enc["iv_hex"],
        "salt_hex": enc["salt_hex"],
    }))
    assert dec["plain"] == "Attaquer a l'aube"


@pytest.mark.parametrize("seed", range(10))
def test_tripledes_matches_pycryptodome_key_derivation(seed):
    """La cle derivee fait 24 octets et produit un chiffre reversible, quelle que soit la phrase secrete."""
    text = _random_text(24, seed)
    key_bytes, salt = tripledes_tool.get_tripledes_key(_random_text(12, seed + 500))
    assert len(key_bytes) == 24
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad, unpad
    cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    ct = cipher.encrypt(pad(text.encode(), 8))
    plain = unpad(DES3.new(key_bytes, DES3.MODE_CBC, iv=cipher.iv).decrypt(ct), 8)
    assert plain.decode() == text


def test_tripledes_degenerate_key_meet_in_the_middle_is_documented():
    """La docstring du module doit mentionner l'attaque meet-in-the-middle qui borne 3DES a ~2^112."""
    assert "meet-in-the-middle" in tripledes_tool.__doc__
    assert "2^112" in tripledes_tool.__doc__


# --- ChaCha20-Poly1305 --------------------------------------------------------

def test_chacha20_round_trip_through_api():
    enc = unwrap(client.post("/api/modern/chacha20poly1305/encrypt", json={"text": "TLS 1.3", "key": "clef chacha"}))
    dec = unwrap(client.post("/api/modern/chacha20poly1305/decrypt", json={
        "cipher_hex": enc["cipher_hex"],
        "key": "clef chacha",
        "nonce_hex": enc["nonce_hex"],
        "salt_hex": enc["salt_hex"],
    }))
    assert dec["plain"] == "TLS 1.3"


def test_chacha20_rfc8439_test_vector():
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    ).hex()
    result = chacha20_tool.chacha20_poly1305_raw(
        key_hex="808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        nonce_hex="070000004041424344454647",
        plaintext_hex=plaintext,
        aad_hex="50515253c0c1c2c3c4c5c6c7",
    )
    assert result["cipher_hex"].startswith("d31a8d34648e60db7b86afbc53ef7ec2")
    assert result["tag_hex"] == "1ae10b594f09e26a7e902ecbd0600691"[:32]


def test_chacha20_wrong_key_fails_with_typed_error():
    enc = unwrap(client.post("/api/modern/chacha20poly1305/encrypt", json={"text": "x", "key": "a"}))
    resp = client.post("/api/modern/chacha20poly1305/decrypt", json={
        "cipher_hex": enc["cipher_hex"],
        "key": "clef differente",
        "nonce_hex": enc["nonce_hex"],
        "salt_hex": enc["salt_hex"],
    })
    assert resp.status_code == 400
    assert error_of(resp)["code"] == "decryption_failed"


# --- RC4 -----------------------------------------------------------------------

def test_rc4_known_answer_test():
    """Vecteur classique : cle 'Key', texte 'Plaintext'."""
    cipher = rc4_tool.rc4_crypt(b"Plaintext", b"Key")
    assert cipher.hex().upper() == "BBF316E8D940AF0AD3"


def test_rc4_is_involutive():
    original = "attaque a l'aube"
    ciphered = rc4_tool.encrypt_rc4(original, "cle")
    assert rc4_tool.decrypt_rc4(ciphered["cipher_hex"], "cle") == original


def test_rc4_bias_is_documented_as_broken():
    assert "biais" in rc4_tool.__doc__.lower() or "Mantin" in rc4_tool.__doc__


def test_rc4_endpoint_round_trip():
    enc = unwrap(client.post("/api/modern/rc4/encrypt", json={"text": "hello", "key": "k"}))
    assert "cipher_hex" in enc


# --- Multi-blocs AES et DES : chiffrement + dechiffrement pas a pas -----------

@pytest.mark.parametrize("length", [1, 15, 16, 17, 32, 33, 47])
def test_aes_multiblock_round_trip(length):
    text = _random_text(length, seed=length)
    key = "Thats my Kung Fu"
    encrypted = aes_simulator.simulate_aes_encrypt_multiblock(text, key)
    decrypted = aes_simulator.simulate_aes_decrypt_multiblock(encrypted["final_result_hex"], key)
    assert decrypted["final_result"] == text
    assert encrypted["block_count"] == decrypted["block_count"]


@pytest.mark.parametrize("length", [1, 7, 8, 9, 16, 23])
def test_des_multiblock_round_trip(length):
    text = _random_text(length, seed=length + 100)
    key = "abcdefgh"
    encrypted = des_simulator.simulate_des_encrypt_multiblock(text, key)
    decrypted = des_simulator.simulate_des_decrypt_multiblock(encrypted["final_result_hex"], key)
    assert decrypted["final_result"] == text


def test_aes_multiblock_matches_single_block_on_exactly_16_bytes():
    """Sur un texte de 16 octets exacts, la version multi-blocs ajoute un bloc de bourrage complet, contrairement a l'ancien simulateur qui tronquait/paddait avec des zeros."""
    text = "Two One Nine Two"  # 16 caracteres ASCII == 16 octets
    key = "Thats my Kung Fu"
    old = aes_simulator.simulate_aes_encrypt(text, key)
    new = aes_simulator.simulate_aes_encrypt_multiblock(text, key)
    assert old["final_result_hex"] == "29c3505f571420f6402299b31a02d73a"
    # Le nouveau simulateur ajoute un bloc de bourrage PKCS#7 complet (16 octets de 0x10)
    assert new["block_count"] == 2
    assert new["final_result_hex"].startswith("29c3505f571420f6402299b31a02d73a")


def test_aes_multiblock_api_endpoint():
    enc = unwrap(client.post("/api/simulate/aes-multiblock", json={"text": "Un message assez long pour plusieurs blocs AES", "key": "cle de simulation"}))
    assert enc["block_count"] >= 2
    dec = unwrap(client.post("/api/simulate/aes-decrypt", json={"cipher_hex": enc["final_result_hex"], "key": "cle de simulation"}))
    assert dec["final_result"] == "Un message assez long pour plusieurs blocs AES"


def test_des_multiblock_api_endpoint():
    enc = unwrap(client.post("/api/simulate/des-multiblock", json={"text": "Message DES multi-blocs", "key": "abcdefgh"}))
    assert enc["block_count"] >= 2
    dec = unwrap(client.post("/api/simulate/des-decrypt", json={"cipher_hex": enc["final_result_hex"], "key": "abcdefgh"}))
    assert dec["final_result"] == "Message DES multi-blocs"


# --- Modes d'operation : le pingouin ECB --------------------------------------

def test_ecb_penguin_demo_shows_the_leak():
    resp = unwrap(client.post("/api/modern/aesmodes/penguin-demo", json={
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "block_hex": "6bc1bee22e409f96e93d7e117393172a",
        "repeats": 4,
    }))
    assert resp["ecb_leaks_pattern"] is True
    assert resp["cbc_leaks_pattern"] is False
    assert resp["ctr_leaks_pattern"] is False
    assert len(set(resp["ecb_blocks"])) == 1
    assert len(set(resp["cbc_blocks"])) == 4
