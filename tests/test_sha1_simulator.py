"""
Simulateur SHA-1 : trace pas a pas validee contre les vecteurs officiels
RFC 3174 / FIPS 180-1 et contre hashlib sur des entrees variees.

SHA-1 est CASSE (SHAttered, 2017) : ces tests prouvent que la simulation
reproduit fidelement l'algorithme historique, pas qu'il est sur a utiliser.
"""

import hashlib
import random
import string

import pytest

from utils import sha1_tool, step_visualizer

ASCII_PRINTABLE = string.ascii_letters + string.digits + " .,!?-"


def _random_text(length: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(ASCII_PRINTABLE) for _ in range(length))


def test_sha1_empty_string_vector():
    """RFC 3174 / FIPS 180-1, empreinte de la chaine vide."""
    result = step_visualizer.simulate_sha1("")
    assert result["final_result"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_sha1_abc_vector():
    """RFC 3174, section 7.3, exemple 1."""
    result = step_visualizer.simulate_sha1("abc")
    assert result["final_result"] == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_sha1_two_block_vector():
    """RFC 3174, section 7.3, exemple 2 : message assez long pour forcer deux blocs."""
    text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    result = step_visualizer.simulate_sha1(text)
    assert result["final_result"] == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    assert result["block_count"] == 2


@pytest.mark.parametrize("seed", range(20))
def test_sha1_simulator_matches_hashlib(seed):
    text = _random_text(seed + 1, seed)
    expected = hashlib.sha1(text.encode("utf-8")).hexdigest()
    assert step_visualizer.simulate_sha1(text)["final_result"] == expected


def test_sha1_from_scratch_matches_hashlib():
    for text in ("", "abc", "CryptoLab", "a" * 1000):
        expected = hashlib.sha1(text.encode("utf-8")).hexdigest()
        assert sha1_tool.sha1_from_scratch(text.encode("utf-8")) == expected


def test_sha1_trace_has_80_rounds_per_block():
    steps = step_visualizer.simulate_sha1("abc")["steps"]
    compression_steps = [s for s in steps if s["phase"] == "Compression"]
    assert len(compression_steps) == 80
    assert [s["round"] for s in compression_steps] == list(range(80))


def test_sha1_trace_ends_with_final_digest():
    steps = step_visualizer.simulate_sha1("abc")["steps"]
    assert steps[-1]["phase"] == "Final"
    assert steps[-1]["final_result"] == step_visualizer.simulate_sha1("abc")["final_result"]
