"""
Hachage, AES-GCM, DES-CBC et RSA-OAEP : vecteurs et proprietes.
"""

import pytest

from utils import aes_tool, des_tool, hash_tool, rsa_tool

# --- SHA-256 (vecteurs NIST) -------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        ("a" * 1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"),
    ],
)
def test_sha256_nist_vectors(text, expected):
    assert hash_tool.hash_sha256(text) == expected


def test_sha256_avalanche():
    """Un seul bit change doit modifier environ la moitie des bits de sortie."""
    a = bytes.fromhex(hash_tool.hash_sha256("CryptoLab"))
    b = bytes.fromhex(hash_tool.hash_sha256("CryptoLac"))
    differing_bits = sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))
    assert 80 < differing_bits < 176  # 256 bits, attendu ~128


def test_sha256_is_deterministic():
    assert hash_tool.hash_sha256("meme entree") == hash_tool.hash_sha256("meme entree")


# --- bcrypt ------------------------------------------------------------------

def test_bcrypt_verifies_correct_password():
    hashed = hash_tool.hash_bcrypt("motdepasse")
    assert hash_tool.verify_bcrypt("motdepasse", hashed) is True


def test_bcrypt_rejects_wrong_password():
    hashed = hash_tool.hash_bcrypt("motdepasse")
    assert hash_tool.verify_bcrypt("mauvais", hashed) is False


def test_bcrypt_is_salted():
    """Deux hachages du meme mot de passe doivent differer."""
    assert hash_tool.hash_bcrypt("identique") != hash_tool.hash_bcrypt("identique")


def test_bcrypt_rejects_malformed_hash():
    assert hash_tool.verify_bcrypt("motdepasse", "pas-un-hash") is False


# --- AES-GCM -----------------------------------------------------------------

def test_aes_gcm_round_trip():
    result = aes_tool.encrypt_aes_gcm("Message secret", "ma-cle")
    plain = aes_tool.decrypt_aes_gcm(
        result["cipher_hex"], "ma-cle", result["nonce_hex"], result["tag_hex"]
    )
    assert plain == "Message secret"


def test_aes_gcm_uses_a_fresh_nonce_each_time():
    first = aes_tool.encrypt_aes_gcm("Message", "cle")
    second = aes_tool.encrypt_aes_gcm("Message", "cle")
    assert first["nonce_hex"] != second["nonce_hex"]
    assert first["cipher_hex"] != second["cipher_hex"]


def test_aes_gcm_rejects_wrong_key():
    result = aes_tool.encrypt_aes_gcm("Message secret", "bonne-cle")
    plain = aes_tool.decrypt_aes_gcm(
        result["cipher_hex"], "mauvaise-cle", result["nonce_hex"], result["tag_hex"]
    )
    assert plain.startswith("Erreur")


def test_aes_gcm_detects_tampering():
    """C'est tout l'interet du mode authentifie : un bit modifie est detecte."""
    result = aes_tool.encrypt_aes_gcm("Message secret", "cle")
    tampered = bytearray(bytes.fromhex(result["cipher_hex"]))
    tampered[0] ^= 0x01

    plain = aes_tool.decrypt_aes_gcm(
        tampered.hex(), "cle", result["nonce_hex"], result["tag_hex"]
    )
    assert plain.startswith("Erreur")


def test_aes_key_derivation_is_32_bytes():
    assert len(aes_tool.get_aes_key("n'importe quelle phrase")) == 32


# --- DES-CBC -----------------------------------------------------------------

def test_des_cbc_round_trip():
    result = des_tool.encrypt_des_cbc("Message secret", "ma-cle")
    plain = des_tool.decrypt_des_cbc(result["cipher_hex"], "ma-cle", result["iv_hex"])
    assert plain == "Message secret"


def test_des_cbc_uses_a_fresh_iv_each_time():
    first = des_tool.encrypt_des_cbc("Message", "cle")
    second = des_tool.encrypt_des_cbc("Message", "cle")
    assert first["iv_hex"] != second["iv_hex"]


def test_des_cbc_rejects_wrong_key():
    result = des_tool.encrypt_des_cbc("Message secret", "bonne-cle")
    plain = des_tool.decrypt_des_cbc(result["cipher_hex"], "mauvaise-cle", result["iv_hex"])
    assert plain.startswith("Erreur")


def test_des_key_derivation_is_8_bytes():
    assert len(des_tool.get_des_key("n'importe quelle phrase")) == 8


# --- RSA-OAEP ----------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa_keys():
    return rsa_tool.generate_rsa_keys()


def test_rsa_generates_a_pem_key_pair(rsa_keys):
    assert rsa_keys["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY-----" in rsa_keys["private_key"]


def test_rsa_round_trip(rsa_keys):
    cipher = rsa_tool.encrypt_rsa("Message secret", rsa_keys["public_key"])
    assert rsa_tool.decrypt_rsa(cipher, rsa_keys["private_key"]) == "Message secret"


def test_rsa_is_probabilistic(rsa_keys):
    """OAEP ajoute de l'aleatoire : deux chiffrements du meme message different."""
    first = rsa_tool.encrypt_rsa("Message", rsa_keys["public_key"])
    second = rsa_tool.encrypt_rsa("Message", rsa_keys["public_key"])
    assert first != second


def test_rsa_rejects_wrong_private_key(rsa_keys):
    other = rsa_tool.generate_rsa_keys()
    cipher = rsa_tool.encrypt_rsa("Message", rsa_keys["public_key"])
    assert rsa_tool.decrypt_rsa(cipher, other["private_key"]).startswith("Erreur")


def test_rsa_rejects_invalid_public_key():
    assert rsa_tool.encrypt_rsa("Message", "pas-une-cle").startswith("Erreur")


def test_rsa_rejects_text_that_is_too_long(rsa_keys):
    """RSA-2048 avec OAEP ne peut pas chiffrer plus de 214 octets."""
    assert rsa_tool.encrypt_rsa("A" * 500, rsa_keys["public_key"]).startswith("Erreur")
