"""Blowfish-CBC et Camellia-128-CBC (finalistes/candidats du concours AES)."""

import pytest

from registry.errors import DecryptionFailed
from utils import finalists_tool


def test_blowfish_ecb_block_matches_official_test_vector():
    # Bruce Schneier, vecteurs de test Blowfish officiels (cle nulle).
    result = finalists_tool.blowfish_ecb_block_hex("0000000000000000", "0000000000000000")
    assert result["cipher_hex"] == "4ef997456198dd78"


def test_camellia_ecb_block_matches_rfc3713_vector():
    result = finalists_tool.camellia_ecb_block_hex(
        "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210"
    )
    assert result["cipher_hex"] == "67673138549669730857065648eabe43"


def test_blowfish_cbc_roundtrip():
    enc = finalists_tool.encrypt_blowfish_cbc("Blowfish, precurseur de Twofish.", "phrase secrete")
    plain = finalists_tool.decrypt_blowfish_cbc(enc["cipher_hex"], "phrase secrete", enc["iv_hex"], enc["salt_hex"])
    assert plain == "Blowfish, precurseur de Twofish."


def test_camellia_cbc_roundtrip():
    enc = finalists_tool.encrypt_camellia_cbc("Camellia, retenu par CRYPTREC.", "phrase secrete")
    plain = finalists_tool.decrypt_camellia_cbc(enc["cipher_hex"], "phrase secrete", enc["iv_hex"], enc["salt_hex"])
    assert plain == "Camellia, retenu par CRYPTREC."


def test_blowfish_cbc_wrong_key_fails_cleanly():
    enc = finalists_tool.encrypt_blowfish_cbc("secret", "bonne cle")
    with pytest.raises(DecryptionFailed):
        finalists_tool.decrypt_blowfish_cbc(enc["cipher_hex"], "mauvaise cle", enc["iv_hex"], enc["salt_hex"])


def test_camellia_cbc_wrong_key_fails_cleanly():
    enc = finalists_tool.encrypt_camellia_cbc("secret", "bonne cle")
    with pytest.raises(DecryptionFailed):
        finalists_tool.decrypt_camellia_cbc(enc["cipher_hex"], "mauvaise cle", enc["iv_hex"], enc["salt_hex"])
