"""
Signature RSA de production : PKCS#1 v1.5 et RSA-PSS.

Signer n'est pas chiffrer, meme si les deux utilisent la meme paire de cles
RSA : chiffrer emploie la cle PUBLIQUE du destinataire (confidentialite),
signer emploie la cle PRIVEE du signataire (authenticite + integrite), et se
verifie avec la cle publique. `utils/rsa_small.py` montre cette inversion sur
des petits nombres ; ici, RSA-2048 reel via `pyca/cryptography`.

RSA-PSS (RFC 8017 §8.1, standardise par PKCS#1 v2.1) ajoute un sel aleatoire :
deux signatures du meme message different a chaque appel — contrairement a
PKCS#1 v1.5, deterministe. C'est pourquoi PSS est recommande pour les
nouveaux usages (SP 800-131A), meme si v1.5 reste tres repandu (ex: TLS
historique).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from registry.errors import InvalidInput, InvalidKey


def generate_rsa_signing_keys() -> dict:
    """Genere une paire de cles RSA-2048 dediee a la signature (memes formats PEM que rsa_tool)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


def _load_private(pem: str) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise InvalidKey("Cle privee RSA illisible : format PEM PKCS#8 attendu.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise InvalidKey("La cle fournie n'est pas une cle RSA.")
    return key


def _load_public(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except ValueError as exc:
        raise InvalidKey("Cle publique RSA illisible : format PEM attendu.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidKey("La cle fournie n'est pas une cle RSA.")
    return key


def sign_rsa_pkcs1v15(message: str, private_key_pem: str) -> dict:
    """Signature PKCS#1 v1.5 (deterministe : signer deux fois le meme message donne la meme signature)."""
    private_key = _load_private(private_key_pem)
    signature = private_key.sign(message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    return {"signature_hex": signature.hex()}


def verify_rsa_pkcs1v15(message: str, signature_hex: str, public_key_pem: str) -> dict:
    public_key = _load_public(public_key_pem)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise InvalidInput("signature_hex doit etre hexadecimal.") from exc
    try:
        public_key.verify(signature, message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}


def sign_rsa_pss(message: str, private_key_pem: str) -> dict:
    """
    Signature RSA-PSS (probabiliste : un sel aleatoire de la taille du hash
    fait qu'aucune signature ne se repete, meme sur le meme message et la
    meme cle).
    """
    private_key = _load_private(private_key_pem)
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {"signature_hex": signature.hex()}


def verify_rsa_pss(message: str, signature_hex: str, public_key_pem: str) -> dict:
    public_key = _load_public(public_key_pem)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise InvalidInput("signature_hex doit etre hexadecimal.") from exc
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}
