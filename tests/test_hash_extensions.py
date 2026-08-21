"""
Sprint 4 : HMAC, MD5, SHA-1, SHA-3-256, BLAKE2b, PBKDF2, scrypt, et le facteur
de cout reglable de bcrypt.

Chaque primitive est verifiee contre un vecteur officiel (RFC/FIPS) et, quand
c'est pertinent, comparee a `hashlib`/`hmac` sur des entrees variees.
"""

import hashlib
import hmac as hmac_lib

import pytest

from utils import hash_tool

# --- HMAC-SHA256 --------------------------------------------------------------

def test_hmac_sha256_rfc4231_case_1():
    assert hash_tool.hmac_sha256("\x0b" * 20, "Hi There") == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


def test_hmac_sha256_rfc4231_case_2():
    assert hash_tool.hmac_sha256("Jefe", "what do ya want for nothing?") == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


@pytest.mark.parametrize("key,message", [("cle", "message"), ("", "x"), ("a" * 100, "b" * 500)])
def test_hmac_sha256_matches_python_hmac(key, message):
    expected = hmac_lib.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
    assert hash_tool.hmac_sha256(key, message) == expected


def test_hmac_sha256_verify_accepts_correct_mac():
    mac = hash_tool.hmac_sha256("cle", "message")
    assert hash_tool.verify_hmac_sha256("cle", "message", mac) is True


def test_hmac_sha256_verify_rejects_tampered_message():
    mac = hash_tool.hmac_sha256("cle", "message")
    assert hash_tool.verify_hmac_sha256("cle", "message altere", mac) is False


def test_hmac_sha256_verify_rejects_malformed_mac():
    assert hash_tool.verify_hmac_sha256("cle", "message", "pas-du-hex") is False


def test_length_extension_demo_shows_the_hash_changes():
    """
    Illustre le probleme qu'HMAC resout : un SHA-256 nu depend entierement de
    `secret || message`, et changer le message change le condense de facon
    reproductible sans jamais avoir eu besoin de HMAC pour s'en proteger.
    """
    result = hash_tool.demonstrate_length_extension_vulnerability("secret", "message")
    assert result["original_hash"] != result["extended_hash"]
    assert len(result["original_hash"]) == 64


# --- MD5 : casse, teste pour l'histoire ---------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
    ],
)
def test_md5_rfc1321_vectors(text, expected):
    assert hash_tool.hash_md5(text) == expected


def test_md5_collision_pair_has_identical_hash():
    """
    Paire de collision MD5 classique (Wang, Yu 2004 / variantes largement
    documentees) : deux blocs de 128 octets distincts, meme empreinte MD5.
    Prouve que la resistance aux collisions n'existe plus.
    """
    block_a = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    block_b = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
    )
    assert hashlib.md5(block_a).hexdigest() == hashlib.md5(block_b).hexdigest()
    assert block_a != block_b


# --- SHA-1 : casse, teste pour l'histoire -------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ],
)
def test_sha1_vectors(text, expected):
    assert hash_tool.hash_sha1(text) == expected


def test_sha1_from_scratch_matches_hashlib_path():
    assert hash_tool.hash_sha1_from_scratch("abc") == hash_tool.hash_sha1("abc")


# --- SHA-3-256 -----------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ],
)
def test_sha3_256_vectors(text, expected):
    assert hash_tool.hash_sha3_256(text) == expected


# --- BLAKE2b ---------------------------------------------------------------------

def test_blake2b_empty_string_vector():
    """RFC 7693, appendice A."""
    assert hash_tool.hash_blake2b("") == (
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    )


# --- PBKDF2 ---------------------------------------------------------------------

def test_pbkdf2_rfc6070_vector_1():
    """RFC 6070, cas de test 1 : PBKDF2-HMAC-SHA1(password, salt, c=1, dkLen=20)."""
    derived = hash_tool.pbkdf2_derive(
        "password", b"salt", iterations=1, dklen=20, hash_name="sha1"
    )
    assert derived.hex() == "0c60c80f961f0e71f3a9b524af6012062fe037a6"


def test_pbkdf2_rfc6070_vector_2():
    """RFC 6070, cas de test 2 : 4096 iterations."""
    derived = hash_tool.pbkdf2_derive(
        "password", b"salt", iterations=4096, dklen=20, hash_name="sha1"
    )
    assert derived.hex() == "4b007901b765489abead49d926f721d065a429c1"


def test_pbkdf2_hmac_sha256_rfc7914_vector():
    """RFC 7914, section 11 : PBKDF2-HMAC-SHA256(passwd, salt, c=1, dkLen=64)."""
    derived = hash_tool.pbkdf2_derive("passwd", b"salt", iterations=1, dklen=64)
    assert derived.hex() == (
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    )


def test_pbkdf2_different_salts_give_different_keys():
    a = hash_tool.pbkdf2_derive("meme-mot-de-passe", b"\x00" * 16, iterations=100)
    b = hash_tool.pbkdf2_derive("meme-mot-de-passe", b"\x01" * 16, iterations=100)
    assert a != b


# --- scrypt ----------------------------------------------------------------------

def test_scrypt_rfc7914_vector_1():
    """RFC 7914, section 12, cas de test 1 : P='', S='', N=16, r=1, p=1, dkLen=64."""
    derived = hash_tool.scrypt_derive("", b"", n=16, r=1, p=1, dklen=64)
    assert derived.hex() == (
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    )


def test_scrypt_different_salts_give_different_keys():
    a = hash_tool.scrypt_derive("meme-mot-de-passe", b"\x00" * 16, n=16, r=1, p=1)
    b = hash_tool.scrypt_derive("meme-mot-de-passe", b"\x01" * 16, n=16, r=1, p=1)
    assert a != b


# --- bcrypt : facteur de cout reglable --------------------------------------------

def test_bcrypt_default_cost_round_trips():
    hashed = hash_tool.hash_bcrypt("motdepasse")
    assert hash_tool.verify_bcrypt("motdepasse", hashed) is True


def test_bcrypt_higher_cost_is_measurably_slower():
    """
    Un cout plus eleve doit prendre plus longtemps : c'est tout l'interet du
    facteur de travail face a un attaquant qui teste des mots de passe en
    boucle. Marge large (>=1.3x) pour ne pas etre instable en CI.
    """
    low = hash_tool.time_bcrypt("motdepasse", cost=4)
    high = hash_tool.time_bcrypt("motdepasse", cost=10)
    assert high > low * 1.3
