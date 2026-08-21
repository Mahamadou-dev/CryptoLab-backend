"""
DSA (Digital Signature Algorithm, FIPS 186-4) — couche production
(`pyca/cryptography`).

Fonde sur le meme probleme que Diffie-Hellman et ElGamal (logarithme
discret dans (Z/pZ)*), mais utilise pour signer plutot que pour chiffrer ou
echanger une cle : la meme famille mathematique sert trois usages distincts,
c'est le fil qui relie DH, ElGamal et DSA dans Sprint 6.

Signature probabiliste comme ECDSA : un nonce k aleatoire different a
chaque signature. Un k reutilise ou previsible expose x (cle privee)
directement — meme categorie de faille que le vol de cles PS3 (ECDSA) ou
la reutilisation de k en ElGamal.

DSA est deprecie pour du code neuf (NIST le retire de FIPS 186-5 au profit
d'ECDSA/EdDSA) : presente ici pour son interet historique et pedagogique
(cle publique X.509, ancien standard federal americain 1994-2023), pas
comme recommandation.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa

from registry.errors import InvalidInput, InvalidKey


def generate_dsa_keys() -> dict:
    """Genere une paire de cles DSA (parametres 2048 bits, taille minimale FIPS 186-4 actuelle)."""
    key = dsa.generate_private_key(key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return {"private_key": private_pem, "public_key": public_pem}


def _load_dsa_private(pem: str) -> dsa.DSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise InvalidKey("Cle privee DSA illisible : format PEM PKCS#8 attendu.") from exc
    if not isinstance(key, dsa.DSAPrivateKey):
        raise InvalidKey("La cle fournie n'est pas une cle DSA.")
    return key


def _load_dsa_public(pem: str) -> dsa.DSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        raise InvalidKey("Cle publique DSA illisible : format PEM attendu.") from exc
    if not isinstance(key, dsa.DSAPublicKey):
        raise InvalidKey("La cle fournie n'est pas une cle DSA.")
    return key


def sign_dsa(message: str, private_key_pem: str) -> dict:
    """Signe avec DSA + SHA-256. Le nonce k est tire au hasard a chaque appel (probabiliste)."""
    private_key = _load_dsa_private(private_key_pem)
    signature = private_key.sign(message.encode("utf-8"), hashes.SHA256())
    return {"signature_hex": signature.hex()}


def verify_dsa(message: str, signature_hex: str, public_key_pem: str) -> dict:
    public_key = _load_dsa_public(public_key_pem)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise InvalidInput("signature_hex doit etre hexadecimal.") from exc
    try:
        public_key.verify(signature, message.encode("utf-8"), hashes.SHA256())
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}
