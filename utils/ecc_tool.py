"""
Courbes elliptiques : addition et doublement de points, en Python pur.

Couche pedagogique — la couche production (ECDH, ECDSA, Ed25519) delegue a
`pyca/cryptography` ailleurs (`dh_tool.py`, `signature_tool.py`). Ici, le but
est de montrer CE QUE `P + Q` signifie geometriquement sur une courbe
`y^2 = x^3 + a*x + b mod p` : la loi de groupe qui fonde toute la cryptographie
a courbe elliptique.

Deux courbes exposees :
- secp256k1 (Bitcoin, Ethereum) : a = 0, b = 7.
- Curve25519 n'est PAS une courbe de Weierstrass (c'est une courbe de
  Montgomery, `y^2 = x^3 + 486662*x^2 + x`) : l'addition ci-dessous ne
  s'applique pas telle quelle. Sa version production (X25519) est couverte
  par `dh_tool.ecdh_x25519_*`.
"""

from __future__ import annotations

from dataclasses import dataclass

from registry.errors import InvalidInput

# secp256k1 (SEC 2, v2, section 2.4.1)
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Point = tuple[int, int] | None  # None = point a l'infini (element neutre)


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int

    def on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        x, y = point
        return (y * y - (x**3 + self.a * x + self.b)) % self.p == 0


SECP256K1 = Curve(p=SECP256K1_P, a=SECP256K1_A, b=SECP256K1_B)
SECP256K1_G: Point = (SECP256K1_GX, SECP256K1_GY)


def _mod_inverse(x: int, p: int) -> int:
    return pow(x, p - 2, p)  # p premier : petit theoreme de Fermat


def point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    """
    Addition de deux points sur `curve`.

    Geometriquement : la droite passant par P et Q recoupe la courbe en un
    troisieme point, dont le symetrique par rapport a l'axe des x est P + Q.
    Cas particuliers : element neutre (point a l'infini), P + (-P) = infini,
    et P == Q (voir `point_double`, qui utilise la tangente).
    """
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None  # P + (-P) = point a l'infini

    if p1 == p2:
        return point_double(curve, p1)

    slope = ((y2 - y1) * _mod_inverse((x2 - x1) % curve.p, curve.p)) % curve.p
    x3 = (slope * slope - x1 - x2) % curve.p
    y3 = (slope * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def point_double(curve: Curve, point: Point) -> Point:
    """Double un point (P + P), via la tangente a la courbe en P."""
    if point is None:
        return None
    x, y = point
    if y == 0:
        return None
    slope = ((3 * x * x + curve.a) * _mod_inverse((2 * y) % curve.p, curve.p)) % curve.p
    x3 = (slope * slope - 2 * x) % curve.p
    y3 = (slope * (x - x3) - y) % curve.p
    return (x3, y3)


def scalar_multiply(curve: Curve, k: int, point: Point) -> Point:
    """k * P par doublement-et-addition (l'operation au coeur d'ECDH/ECDSA)."""
    if k < 0:
        raise InvalidInput("Le scalaire doit etre positif.")
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_double(curve, addend)
        k >>= 1
    return result


def secp256k1_point_add(x1: int, y1: int, x2: int, y2: int) -> dict:
    """API : additionne deux points de secp256k1 fournis en coordonnees affines."""
    p1, p2 = (x1, y1), (x2, y2)
    if not SECP256K1.on_curve(p1) or not SECP256K1.on_curve(p2):
        raise InvalidInput("Un des deux points fournis n'est pas sur la courbe secp256k1.")
    result = point_add(SECP256K1, p1, p2)
    return {"result": None if result is None else {"x": result[0], "y": result[1]}}


def secp256k1_scalar_multiply(k: int, x: int, y: int) -> dict:
    """API : calcule k * P sur secp256k1, P fourni en coordonnees affines."""
    point = (x, y)
    if not SECP256K1.on_curve(point):
        raise InvalidInput("Le point fourni n'est pas sur la courbe secp256k1.")
    if not 0 < k < SECP256K1_N:
        raise InvalidInput(f"Le scalaire doit verifier 0 < k < n (n = {SECP256K1_N}).")
    result = scalar_multiply(SECP256K1, k, point)
    return {"result": None if result is None else {"x": result[0], "y": result[1]}}
