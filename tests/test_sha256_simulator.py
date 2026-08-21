"""
Simulateur SHA-256 : trace pas a pas validee contre les vecteurs officiels
FIPS 180-4 et contre hashlib sur des entrees variees.
"""

import hashlib
import random
import string

import pytest

from utils import step_visualizer

ASCII_PRINTABLE = string.ascii_letters + string.digits + " .,!?-"


def _random_text(length: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(ASCII_PRINTABLE) for _ in range(length))


def test_sha256_empty_string_vector():
    """FIPS 180-4, empreinte de la chaine vide."""
    result = step_visualizer.simulate_sha256("")
    assert result["final_result"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_abc_vector():
    """FIPS 180-4, exemple B.1."""
    result = step_visualizer.simulate_sha256("abc")
    assert result["final_result"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_two_block_vector():
    """FIPS 180-4, exemple B.2 : message assez long pour forcer deux blocs."""
    text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    result = step_visualizer.simulate_sha256(text)
    assert result["final_result"] == (
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )
    assert result["block_count"] == 2


def test_sha256_single_block_for_short_input():
    assert step_visualizer.simulate_sha256("abc")["block_count"] == 1


@pytest.mark.parametrize("seed", range(20))
def test_sha256_simulator_matches_hashlib(seed):
    text = _random_text(seed + 1, seed)
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert step_visualizer.simulate_sha256(text)["final_result"] == expected


def test_sha256_trace_has_64_rounds_per_block():
    steps = step_visualizer.simulate_sha256("abc")["steps"]
    compression_steps = [s for s in steps if s["phase"] == "Compression"]
    assert len(compression_steps) == 64
    assert [s["round"] for s in compression_steps] == list(range(64))


def test_sha256_trace_ends_with_final_digest():
    steps = step_visualizer.simulate_sha256("abc")["steps"]
    assert steps[-1]["phase"] == "Final"
    assert steps[-1]["final_result"] == step_visualizer.simulate_sha256("abc")["final_result"]
