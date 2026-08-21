"""
RSA en "petits nombres" — couche strictement pedagogique, Python pur, tracee.

RSA-2048 (`utils/rsa_tool.py`) chiffre correctement mais cache tout le calcul
derriere `Crypto.PublicKey.RSA.generate`. Ici, p et q sont deux petits nombres
premiers fournis par l'appelant (ou tires au hasard dans un intervalle
minuscule) : n, phi(n), e et d se calculent a la main, et chaque etape est
tracee. Le message chiffre est un entier, pas un texte — a cette echelle
(quelques centaines), il n'y a pas de remplissage (padding) et jamais assez de
place pour un texte reel. **Ceci ne protege rien : c'est le meme algorithme
que RSA-2048, en amphi plutot qu'en production.**
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd

from registry.errors import InvalidInput


def _is_probable_prime(n: int) -> bool:
    """Primalite par essais de division : suffisant pour de petits nombres pedagogiques."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Algorithme d'Euclide etendu : renvoie (pgcd, x, y) tel que a*x + b*y = pgcd."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(e: int, phi: int) -> int:
    """Inverse modulaire de e mod phi, via Euclide etendu. Leve si e et phi ne sont pas premiers entre eux."""
    g, x, _ = _extended_gcd(e, phi)
    if g != 1:
        raise InvalidInput(f"{e} n'a pas d'inverse modulo {phi} : pgcd = {g} != 1.")
    return x % phi


@dataclass(frozen=True)
class SmallRsaKeys:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int
    steps: list[str]


def generate_small_rsa(p: int, q: int, e: int = 65537) -> SmallRsaKeys:
    """
    Genere une paire de cles RSA "a la main" a partir de deux petits premiers.

    Trace chaque etape : n = p*q, phi(n) = (p-1)(q-1), choix de e premier avec
    phi(n), calcul de d = e^-1 mod phi(n) par Euclide etendu.
    """
    if not _is_probable_prime(p) or not _is_probable_prime(q):
        raise InvalidInput("p et q doivent tous les deux etre premiers.")
    if p == q:
        raise InvalidInput("p et q doivent etre distincts (n = p*q serait un carre parfait).")
    if p < 2 or q < 2:
        raise InvalidInput("p et q doivent etre superieurs a 1.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if e <= 1 or e >= phi or gcd(e, phi) != 1:
        raise InvalidInput(
            f"e={e} doit verifier 1 < e < phi(n)={phi} et etre premier avec phi(n) "
            f"(pgcd(e, phi)={gcd(e, phi)})."
        )

    d = mod_inverse(e, phi)

    steps = [
        f"n = p * q = {p} * {q} = {n}",
        f"phi(n) = (p-1)(q-1) = {p - 1} * {q - 1} = {phi}",
        f"e = {e} choisi tel que pgcd(e, phi(n)) = 1 (verifie : pgcd({e}, {phi}) = {gcd(e, phi)})",
        f"d = e^-1 mod phi(n), par l'algorithme d'Euclide etendu : d = {d}",
        f"Verification : (e * d) mod phi(n) = ({e} * {d}) mod {phi} = {(e * d) % phi} (doit valoir 1)",
    ]

    return SmallRsaKeys(p=p, q=q, n=n, phi=phi, e=e, d=d, steps=steps)


def encrypt_small_rsa(message: int, e: int, n: int) -> dict:
    """Chiffre un entier m < n : c = m^e mod n."""
    if not 0 <= message < n:
        raise InvalidInput(f"Le message doit verifier 0 <= m < n (n={n}). RSA petits nombres ne remplit pas.")
    cipher = pow(message, e, n)
    return {"cipher": cipher, "steps": [f"c = m^e mod n = {message}^{e} mod {n} = {cipher}"]}


def decrypt_small_rsa(cipher: int, d: int, n: int) -> dict:
    """Dechiffre : m = c^d mod n."""
    if not 0 <= cipher < n:
        raise InvalidInput(f"Le chiffre doit verifier 0 <= c < n (n={n}).")
    plain = pow(cipher, d, n)
    return {"plain": plain, "steps": [f"m = c^d mod n = {cipher}^{d} mod {n} = {plain}"]}


def sign_small_rsa(message: int, d: int, n: int) -> dict:
    """
    Signature RSA "manuelle" : s = m^d mod n (l'exposant PRIVE signe, contrairement
    au chiffrement ou l'exposant PUBLIC chiffre). C'est cette inversion que les
    etudiants confondent le plus souvent : signer, ce n'est pas chiffrer.
    """
    if not 0 <= message < n:
        raise InvalidInput(f"Le message doit verifier 0 <= m < n (n={n}).")
    signature = pow(message, d, n)
    return {
        "signature": signature,
        "steps": [f"s = m^d mod n = {message}^{d} mod {n} = {signature} (exposant PRIVE, pas public)"],
    }


def verify_small_rsa(message: int, signature: int, e: int, n: int) -> dict:
    """Verifie une signature : m == s^e mod n (exposant PUBLIC, symetrique du chiffrement)."""
    recovered = pow(signature, e, n)
    valid = recovered == (message % n)
    return {
        "valid": valid,
        "recovered": recovered,
        "steps": [
            f"s^e mod n = {signature}^{e} mod {n} = {recovered}",
            f"Signature {'valide' if valid else 'INVALIDE'} : {recovered} {'==' if valid else '!='} m ({message % n})",
        ],
    }
