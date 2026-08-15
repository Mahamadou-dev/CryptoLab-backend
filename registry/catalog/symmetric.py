"""Symetrique moderne : AES et DES."""

from __future__ import annotations

from db.models import AesDecryptInput, DesDecryptInput, KeyTextInput
from registry.spec import Algorithm, Family, Maturity, Operation
from utils import aes_tool, des_tool

AES = Algorithm(
    slug="aes",
    name="AES-256-GCM",
    family=Family.SYMMETRIC,
    summary=(
        "Le standard symetrique actuel, en mode authentifie GCM : le chiffre "
        "porte un tag qui detecte toute alteration."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2001,
    simulator="aes",
    aliases=("rijndael", "gcm"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: aes_tool.encrypt_aes_gcm(d.text, d.key),
            summary="Chiffrer en AES-256-GCM",
            description=(
                "Le nonce est tire au hasard a chaque appel : deux chiffrements "
                "du meme texte avec la meme cle donnent des sorties differentes. "
                "C'est voulu, et c'est ce qui manque a ECB."
            ),
        ),
        Operation(
            name="decrypt",
            input_model=AesDecryptInput,
            handler=lambda d: {
                "plain": aes_tool.decrypt_aes_gcm(d.cipher_hex, d.key, d.nonce_hex, d.tag_hex)
            },
            summary="Dechiffrer et verifier le tag",
            length_field="cipher_hex",
        ),
    ),
    # Le chiffrement GCM tire un nonce aleatoire : aucun vecteur fixe n'est
    # possible sur cette route. Les vecteurs FIPS-197 sont verifies sur le
    # simulateur pas a pas, qui, lui, est deterministe (tests/test_simulators.py).
)

DES = Algorithm(
    slug="des",
    name="DES-CBC",
    family=Family.SYMMETRIC,
    summary=(
        "Le standard de 1977, casse par force brute des 1998. Conserve pour son "
        "reseau de Feistel, qui structure encore la cryptographie moderne."
    ),
    maturity=Maturity.BROKEN,
    difficulty=4,
    year=1977,
    simulator="des",
    aliases=("feistel", "cbc"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: des_tool.encrypt_des_cbc(d.text, d.key),
            summary="Chiffrer en DES-CBC",
        ),
        Operation(
            name="decrypt",
            input_model=DesDecryptInput,
            handler=lambda d: {"plain": des_tool.decrypt_des_cbc(d.cipher_hex, d.key, d.iv_hex)},
            summary="Dechiffrer un DES-CBC",
            length_field="cipher_hex",
        ),
    ),
    # Meme raison qu'AES : l'IV est aleatoire a chaque chiffrement.
)

ALGORITHMS = (AES, DES)
