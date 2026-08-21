"""
SHA-1 pedagogique — implementation depuis zero (FIPS 180-1 / RFC 3174).

SHA-1 est CASSE : la premiere collision publique (deux PDF distincts, meme
empreinte) a ete publiee en 2017 sous le nom SHAttered
(https://shattered.io/). Ce module reste utile pour comprendre la structure
Merkle-Damgard qu'il partage avec SHA-256, mais ne doit jamais servir a
verifier une signature ou une integrite dans un contexte reel.

`hash_tool.hash_sha1` reste le chemin de production (hashlib) ; ce module ne
sert qu'a la simulation pas a pas.
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF

H0 = (
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def pad_message(data: bytes) -> bytes:
    """Bourrage FIPS 180-1 : identique dans sa forme a celui de SHA-256."""
    bit_len = len(data) * 8
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    return padded + bit_len.to_bytes(8, "big")


def message_schedule(block: bytes) -> list[int]:
    """Etend les 16 mots de 32 bits d'un bloc en 80 mots (W[0..79])."""
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 80):
        w.append(_rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    return w


def _round_function(t: int, b: int, c: int, d: int) -> tuple[int, int]:
    """Renvoie (f(t), K(t)) selon la plage du tour (RFC 3174 §5)."""
    if t < 20:
        return (b & c) | (~b & MASK32 & d), 0x5A827999
    if t < 40:
        return b ^ c ^ d, 0x6ED9EBA1
    if t < 60:
        return (b & c) | (b & d) | (c & d), 0x8F1BBCDC
    return b ^ c ^ d, 0xCA62C1D6


def compress(h: tuple[int, ...], w: list[int]) -> tuple[tuple[int, ...], list[dict]]:
    """Les 80 tours de la fonction de compression sur un bloc."""
    a, b, c, d, e = h
    rounds = []
    for t in range(80):
        f, k = _round_function(t, b, c, d)
        temp = (_rotl(a, 5) + f + e + k + w[t]) & MASK32
        e, d, c, b, a = d, c, _rotl(b, 30), a, temp

        rounds.append({
            "round": t,
            "w": w[t],
            "k": k,
            "state": {"a": a, "b": b, "c": c, "d": d, "e": e},
        })
    new_h = (
        (h[0] + a) & MASK32, (h[1] + b) & MASK32,
        (h[2] + c) & MASK32, (h[3] + d) & MASK32,
        (h[4] + e) & MASK32,
    )
    return new_h, rounds


def digest_hex(h: tuple[int, ...]) -> str:
    return "".join(f"{word:08x}" for word in h)


def sha1_from_scratch(data: bytes) -> str:
    """Calcule l'empreinte complete, sans passer par hashlib."""
    padded = pad_message(data)
    blocks = [padded[i:i + 64] for i in range(0, len(padded), 64)]
    h = H0
    for block in blocks:
        w = message_schedule(block)
        h, _ = compress(h, w)
    return digest_hex(h)
