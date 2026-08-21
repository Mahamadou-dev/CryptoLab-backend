"""
Diffie-Hellman et ECDH — le secret partage sans jamais transmettre de secret.

Deux couches :
- `dh_small_numbers` : DH classique sur un petit groupe multiplicatif
  (p, g fournis), trace pas a pas, pour voir le calcul a la main. Alice et Bob
  echangent g^a mod p et g^b mod p ; Eve, qui observe le canal, voit p, g,
  g^a mod p et g^b mod p mais pas a ni b (probleme du logarithme discret) —
  sans grand p, ce probleme est trivial a resoudre, d'ou l'avertissement.
- `ecdh_x25519` : ECDH de production, X25519 (RFC 7748) via `pyca/cryptography`,
  deja utilise pour ChaCha20-Poly1305 et Camellia.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from registry.errors import InvalidInput


def dh_small_numbers(p: int, g: int, a: int, b: int) -> dict:
    """
    Echange Diffie-Hellman "a la main" sur un petit groupe (Z/pZ)*.

    Alice choisit a, calcule A = g^a mod p et l'envoie. Bob choisit b, calcule
    B = g^b mod p et l'envoie. Chacun retombe sur le meme secret partage
    s = g^(ab) mod p SANS que a, b, ni s n'aient jamais transite sur le canal.
    """
    if p < 5:
        raise InvalidInput("p doit etre un nombre premier suffisamment grand pour l'exemple (p >= 5).")
    if not 1 < g < p:
        raise InvalidInput("g doit verifier 1 < g < p.")
    if not 0 < a < p or not 0 < b < p:
        raise InvalidInput("a et b (secrets d'Alice et Bob) doivent verifier 0 < x < p.")

    public_a = pow(g, a, p)
    public_b = pow(g, b, p)
    shared_alice = pow(public_b, a, p)
    shared_bob = pow(public_a, b, p)

    steps = [
        f"Public : p = {p} (modulus premier), g = {g} (generateur)",
        f"Alice choisit un secret a = {a} (jamais transmis), calcule A = g^a mod p = {g}^{a} mod {p} = {public_a}",
        f"Bob choisit un secret b = {b} (jamais transmis), calcule B = g^b mod p = {g}^{b} mod {p} = {public_b}",
        "Alice et Bob s'echangent A et B en clair sur le canal (c'est tout ce qu'Eve voit, avec p et g)",
        f"Alice calcule s = B^a mod p = {public_b}^{a} mod {p} = {shared_alice}",
        f"Bob calcule s = A^b mod p = {public_a}^{b} mod {p} = {shared_bob}",
        f"Les deux secrets partages coincident : {shared_alice} == {shared_bob} = {shared_alice == shared_bob}",
    ]

    return {
        "public_a": public_a,
        "public_b": public_b,
        "shared_secret": shared_alice,
        "secrets_match": shared_alice == shared_bob,
        "steps": steps,
        "eve_sees": {"p": p, "g": g, "public_a": public_a, "public_b": public_b},
        "eve_cannot_recover": "a, b, et le secret partage — casser cela demande de resoudre le logarithme discret.",
    }


def ecdh_x25519_generate() -> dict:
    """Genere une paire de cles X25519 (Curve25519), format brut hexadecimal."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_hex = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    public_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {"private_hex": private_hex, "public_hex": public_hex}


def ecdh_x25519_exchange(private_hex: str, peer_public_hex: str) -> dict:
    """
    Calcule le secret partage X25519 a partir d'une cle privee et d'une
    cle publique paire (RFC 7748). C'est l'ECDH utilise par TLS 1.3, Signal
    et WireGuard.
    """
    try:
        private_bytes = bytes.fromhex(private_hex)
        peer_bytes = bytes.fromhex(peer_public_hex)
    except ValueError as exc:
        raise InvalidInput("private_hex et peer_public_hex doivent etre hexadecimaux.") from exc
    if len(private_bytes) != 32 or len(peer_bytes) != 32:
        raise InvalidInput("Les cles X25519 font exactement 32 octets.")

    try:
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        peer_public_key = X25519PublicKey.from_public_bytes(peer_bytes)
        shared = private_key.exchange(peer_public_key)
    except ValueError as exc:
        raise InvalidInput("Cle X25519 invalide.") from exc

    return {"shared_secret_hex": shared.hex()}
