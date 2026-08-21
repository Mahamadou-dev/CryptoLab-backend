"""
ElGamal — chiffrement a clef publique fonde directement sur le logarithme
discret (contrairement a RSA, fonde sur la factorisation).

Couche pedagogique uniquement, "petits nombres" comme `rsa_small.py` et
`dh_tool.dh_small_numbers` : p, g, x (secret) fournis par l'appelant, calcul
trace pas a pas. Le message est encode comme un entier 0 <= m < p (un seul
"caractere" au sens petit nombre, pas un texte libre) pour rester lisible a
la main.

ElGamal est aussi la brique derriere DSA (signature) et derriere le partage
de secret de Shamir dans son esprit (le secret n'est jamais transmis, seule
une combinaison publique circule). Chiffrement probabiliste : un k aleatoire
different a chaque chiffrement produit un texte chiffre different pour le
meme message clair — propriete IND-CPA, contrairement a RSA manuel.
"""

from __future__ import annotations

import secrets

from registry.errors import InvalidInput


def elgamal_keygen(p: int, g: int, x: int) -> dict:
    """
    Genere une paire de cles ElGamal sur (Z/pZ)* : x est la cle privee
    (0 < x < p-1), la cle publique est (p, g, y = g^x mod p).
    """
    if p < 5:
        raise InvalidInput("p doit etre premier et suffisamment grand pour l'exemple (p >= 5).")
    if not 1 < g < p:
        raise InvalidInput("g doit verifier 1 < g < p.")
    if not 0 < x < p - 1:
        raise InvalidInput("La cle privee x doit verifier 0 < x < p-1.")

    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}


def elgamal_encrypt(p: int, g: int, y: int, m: int, k: int | None = None) -> dict:
    """
    Chiffre un entier m (0 <= m < p) avec la cle publique (p, g, y).

    k est le nonce ephemere (tire aleatoirement s'il n'est pas fourni ;
    fixe ici pour permettre un vecteur de test reproductible — en
    production, k DOIT rester secret et jamais reutilise, exactement comme
    le nonce ECDSA : un k reutilise sur deux chiffrements permet de retrouver
    x directement).

    c1 = g^k mod p, c2 = m * y^k mod p.
    """
    if p < 5 or not 1 < g < p or not 1 < y < p:
        raise InvalidInput("Parametres publics (p, g, y) invalides.")
    if not 0 <= m < p:
        raise InvalidInput("Le message m doit verifier 0 <= m < p.")
    if k is None:
        k = secrets.randbelow(p - 3) + 2
    if not 0 < k < p - 1:
        raise InvalidInput("k (nonce ephemere) doit verifier 0 < k < p-1.")

    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p

    steps = [
        f"Public : p = {p}, g = {g}, cle publique y = g^x mod p = {y}",
        f"Alice tire un nonce ephemere k = {k} (secret, jamais reutilise)",
        f"c1 = g^k mod p = {g}^{k} mod {p} = {c1}",
        f"c2 = m * y^k mod p = {m} * {y}^{k} mod {p} = {c2}",
        f"Texte chiffre envoye a Bob : (c1, c2) = ({c1}, {c2})",
    ]

    return {"c1": c1, "c2": c2, "k": k, "steps": steps}


def elgamal_decrypt(p: int, x: int, c1: int, c2: int) -> dict:
    """
    Dechiffre (c1, c2) avec la cle privee x : m = c2 * (c1^x)^-1 mod p.

    Bob n'a jamais besoin de connaitre k : c1 = g^k mod p suffit pour
    reconstruire le masque y^k mod p = (g^k)^x mod p = c1^x mod p, cote Bob.
    """
    if p < 5 or not 0 < x < p - 1:
        raise InvalidInput("Parametres (p, x) invalides.")
    if not 0 < c1 < p:
        raise InvalidInput("c1 doit verifier 0 < c1 < p.")

    s = pow(c1, x, p)
    s_inv = pow(s, p - 2, p)  # petit theoreme de Fermat : p premier
    m = (c2 * s_inv) % p

    steps = [
        f"Bob calcule s = c1^x mod p = {c1}^{x} mod {p} = {s}",
        f"Bob calcule l'inverse modulaire de s : s^-1 mod p = {s_inv} (petit theoreme de Fermat, p premier)",
        f"m = c2 * s^-1 mod p = {c2} * {s_inv} mod {p} = {m}",
    ]

    return {"m": m, "steps": steps}
