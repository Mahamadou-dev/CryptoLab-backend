"""
Simulateurs AES et DES : validation contre des references externes.

Ces simulateurs sont le coeur pedagogique du projet — c'est eux qui montrent
le key schedule, les S-boxes et les rounds. Ils doivent produire exactement le
meme resultat qu'une bibliotheque auditee, sinon ils enseignent le faux.

La strategie de validation est double :
  1. des vecteurs de reference publies, saisis en dur ;
  2. une comparaison systematique avec PyCryptodome sur des entrees variees,
     ce qui couvre transitivement les vecteurs FIPS-197 / FIPS-46-3.
"""

import random
import string

import pytest
from Crypto.Cipher import AES, DES

from utils import aes_math, aes_simulator, des_simulator

ASCII_16 = string.ascii_letters + string.digits + " .,!?-"


def _random_text(length: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(ASCII_16) for _ in range(length))


# --- AES ---------------------------------------------------------------------

def test_aes_reference_vector():
    """
    Vecteur de reference classique de l'enseignement d'AES-128.
    Clair "Two One Nine Two", cle "Thats my Kung Fu".
    """
    result = aes_simulator.simulate_aes_encrypt("Two One Nine Two", "Thats my Kung Fu")
    assert result["final_result_hex"] == "29c3505f571420f6402299b31a02d73a"


@pytest.mark.parametrize("seed", range(20))
def test_aes_simulator_matches_pycryptodome(seed):
    """Le simulateur doit produire le meme bloc qu'AES-128-ECB de reference."""
    plain = _random_text(16, seed)
    key = _random_text(16, seed + 1000)

    expected = AES.new(key.encode(), AES.MODE_ECB).encrypt(plain.encode()).hex()
    assert aes_simulator.simulate_aes_encrypt(plain, key)["final_result_hex"] == expected


def test_aes_key_schedule_produces_11_round_keys():
    words, _ = aes_simulator.key_to_words("Thats my Kung Fu")
    round_keys, trace = aes_simulator.expand_key(words)
    assert len(round_keys) == 11              # AES-128 : 10 rounds + cle initiale
    assert all(len(rk) == 4 for rk in round_keys)
    assert len(trace) == 41                   # W0-W3 groupes + W4..W43


def test_aes_simulation_has_all_rounds():
    steps = aes_simulator.simulate_aes_encrypt("Two One Nine Two", "Thats my Kung Fu")["steps"]
    rounds = [s["round"] for s in steps if s.get("phase") == "Chiffrement"]
    assert rounds == list(range(11))          # round 0 (AddRoundKey) puis 1..10


def test_aes_final_round_omits_mix_columns():
    steps = aes_simulator.simulate_aes_encrypt("Two One Nine Two", "Thats my Kung Fu")["steps"]
    final_round = next(s for s in steps if s.get("round") == 10)
    assert final_round["mix_columns_out"] == "N/A"


# --- Arithmetique GF(2^8) ----------------------------------------------------

def test_gf_multiplication_by_two():
    # xtime : decalage a gauche, plus 0x1B en cas de debordement
    assert aes_math.gmul_by_02(0x57) == 0xAE
    assert aes_math.gmul_by_02(0xAE) == 0x47


def test_gf_multiplication_reference():
    # Exemple du FIPS-197 : 0x57 * 0x13 = 0xFE
    assert aes_math.gmul(0x57, 0x13) == 0xFE


def test_gf_multiplication_is_commutative():
    for a in (0x00, 0x01, 0x57, 0x83, 0xFF):
        for b in (0x00, 0x01, 0x13, 0x9A, 0xFF):
            assert aes_math.gmul(a, b) == aes_math.gmul(b, a)


def test_mix_columns_reference_column():
    # Colonne de reference du FIPS-197
    assert aes_math.mix_single_column([0xDB, 0x13, 0x53, 0x45]) == [0x8E, 0x4D, 0xA1, 0xBC]


# --- DES ---------------------------------------------------------------------

def test_des_reference_vector():
    result = des_simulator.simulate_des_encrypt("12345678", "abcdefgh")
    assert result["final_result_hex"] == "21C60DA534248BCE"


@pytest.mark.parametrize("seed", range(20))
def test_des_simulator_matches_pycryptodome(seed):
    """Le simulateur doit produire le meme bloc que DES-ECB de reference."""
    plain = _random_text(8, seed)
    key = _random_text(8, seed + 2000)

    expected = DES.new(key.encode(), DES.MODE_ECB).encrypt(plain.encode()).hex().upper()
    assert des_simulator.simulate_des_encrypt(plain, key)["final_result_hex"] == expected


def test_des_generates_16_round_keys():
    key_bits = des_simulator.key_to_bits("abcdefgh")
    round_keys, _ = des_simulator.generate_round_keys(key_bits)
    assert len(round_keys) == 16
    assert all(len(rk) == 48 for rk in round_keys)


def test_des_permutation_helpers():
    assert des_simulator.xor("1100", "1010") == "0110"
    assert des_simulator.shift_left("10110", 2) == "11010"
    assert des_simulator.permute("abcd", [4, 3, 2, 1]) == "dcba"


# --- Traces pas a pas --------------------------------------------------------

@pytest.mark.parametrize(
    "simulate, args",
    [
        (aes_simulator.simulate_aes_encrypt, ("Two One Nine Two", "Thats my Kung Fu")),
        (des_simulator.simulate_des_encrypt, ("12345678", "abcdefgh")),
    ],
)
def test_traces_are_non_empty_and_described(simulate, args):
    """Chaque etape doit porter une description : c'est le produit pedagogique."""
    steps = simulate(*args)["steps"]
    assert len(steps) > 10
    assert all(step.get("description") for step in steps)
