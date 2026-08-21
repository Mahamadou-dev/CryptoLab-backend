"""
ECDSA (secp256k1) et Ed25519 — signatures sur courbe elliptique, couche
production (`pyca/cryptography`).

Completent `rsa_signature_tool.py` (RSA) et `ecc_tool.py` (addition de points
en Python pur, secp256k1) : ici, la loi de groupe elliptique sert a signer, pas
seulement a echanger une cle (`dh_tool.ecdh_x25519_*`).

- ECDSA/secp256k1 : la courbe de Bitcoin et Ethereum. Signature probabiliste
  (nonce k aleatoire a chaque appel) — un k reutilise ou previsible expose la
  cle privee entiere (cause reelle du vol de cles PS3 par le groupe fail0verflow
  en 2010, et de plusieurs vols de bitcoins).
- Ed25519 (RFC 8032) : signature deterministe sur Curve25519 (Twisted Edwards),
  utilisee par SSH, Signal et de plus en plus TLS. Pas de nonce a proteger :
  c'est explicitement l'un des arguments de sa conception.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from registry.errors import InvalidInput, InvalidKey

# --- ECDSA / secp256k1 -------------------------------------------------------

def generate_ecdsa_keys() -> dict:
    """Genere une paire de cles ECDSA sur secp256k1 (format PEM)."""
    key = ec.generate_private_key(ec.SECP256K1())
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


def _load_ecdsa_private(pem: str) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise InvalidKey("Cle privee ECDSA illisible : format PEM PKCS#8 attendu.") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise InvalidKey("La cle fournie n'est pas une cle ECDSA.")
    return key


def _load_ecdsa_public(pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        raise InvalidKey("Cle publique ECDSA illisible : format PEM attendu.") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise InvalidKey("La cle fournie n'est pas une cle ECDSA.")
    return key


def sign_ecdsa(message: str, private_key_pem: str) -> dict:
    """Signe avec ECDSA/secp256k1 + SHA-256. Le nonce k est tire au hasard a chaque appel (probabiliste)."""
    private_key = _load_ecdsa_private(private_key_pem)
    signature = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return {"signature_hex": signature.hex()}


def verify_ecdsa(message: str, signature_hex: str, public_key_pem: str) -> dict:
    public_key = _load_ecdsa_public(public_key_pem)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise InvalidInput("signature_hex doit etre hexadecimal.") from exc
    try:
        public_key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}


# --- Ed25519 (RFC 8032) -------------------------------------------------------

def generate_ed25519_keys() -> dict:
    """Genere une paire de cles Ed25519, format brut hexadecimal (32 octets chacune)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    return {"private_hex": private_hex, "public_hex": public_hex}


def sign_ed25519(message_hex: str, private_hex: str) -> dict:
    """
    Signe avec Ed25519 (deterministe : signer deux fois le meme message avec
    la meme cle donne toujours la meme signature — pas de nonce a proteger).
    Le message est fourni en hexadecimal pour pouvoir rejouer le vecteur
    RFC 8032 §7.1 TEST 1 (message vide) sans ambiguite d'encodage.
    """
    try:
        private_bytes = bytes.fromhex(private_hex)
        message_bytes = bytes.fromhex(message_hex)
    except ValueError as exc:
        raise InvalidInput("private_hex et message_hex doivent etre hexadecimaux.") from exc
    if len(private_bytes) != 32:
        raise InvalidInput("La cle privee Ed25519 fait exactement 32 octets.")

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    signature = private_key.sign(message_bytes)
    return {"signature_hex": signature.hex()}


def verify_ed25519(message_hex: str, signature_hex: str, public_hex: str) -> dict:
    try:
        message_bytes = bytes.fromhex(message_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        public_bytes = bytes.fromhex(public_hex)
    except ValueError as exc:
        raise InvalidInput("message_hex, signature_hex et public_hex doivent etre hexadecimaux.") from exc
    if len(public_bytes) != 32:
        raise InvalidInput("La cle publique Ed25519 fait exactement 32 octets.")

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        public_key.verify(signature_bytes, message_bytes)
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}
