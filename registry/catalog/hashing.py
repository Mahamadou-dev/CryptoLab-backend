"""Hachage et derivation de clefs."""

from __future__ import annotations

from db.models import BcryptVerifyInput, TextInput
from registry.spec import Algorithm, Family, Maturity, Operation, TestVector
from utils import hash_tool

SHA256 = Algorithm(
    slug="sha256",
    name="SHA-256",
    family=Family.HASH,
    summary=(
        "Empreinte de 256 bits, deterministe et a sens unique. Fondation de "
        "Bitcoin, des signatures et de la verification d'integrite."
    ),
    maturity=Maturity.CURRENT,
    difficulty=3,
    year=2001,
    aliases=("sha-2", "empreinte", "digest"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {"hash": hash_tool.hash_sha256(d.text), "input": d.text},
            summary="Calculer l'empreinte SHA-256",
            # L'URL publique est /api/hash/sha256, sans suffixe d'operation.
            path="/sha256",
        ),
    ),
    vectors=(
        TestVector(
            operation="hash",
            inputs={"text": ""},
            expected={
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            source="NIST FIPS 180-4, empreinte de la chaine vide",
        ),
        TestVector(
            operation="hash",
            inputs={"text": "abc"},
            expected={
                "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            },
            source="NIST FIPS 180-4, exemple B.1",
        ),
        TestVector(
            operation="hash",
            inputs={"text": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
            expected={
                "hash": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            },
            source="NIST FIPS 180-4, exemple B.2",
        ),
    ),
)

BCRYPT = Algorithm(
    slug="bcrypt",
    name="bcrypt",
    family=Family.HASH,
    summary=(
        "Hachage de mots de passe volontairement lent, avec sel integre. Deux "
        "appels sur le meme mot de passe donnent deux hachages differents."
    ),
    maturity=Maturity.CURRENT,
    difficulty=3,
    year=1999,
    aliases=("mot de passe", "sel", "salt"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {
                "hash": hash_tool.hash_bcrypt(d.text),
                "note": "Le hachage integre un sel tire au hasard.",
            },
            summary="Hacher un mot de passe",
            path="/bcrypt",
        ),
        Operation(
            name="verify",
            input_model=BcryptVerifyInput,
            handler=lambda d: {
                "match": hash_tool.verify_bcrypt(d.text, d.hashed_text),
                "note": "Vrai si le texte correspond au hachage.",
            },
            summary="Verifier un mot de passe contre son hachage",
            path="/bcrypt/verify",
        ),
    ),
    vectors=(
        TestVector(
            operation="verify",
            inputs={
                "text": "correct horse battery staple",
                # Hachage de reference produit par bcrypt, cout 12.
                "hashed_text": (
                    "$2b$12$iwaB1Vz6yqgx0wOxZIVfJettwCTwQTxjLOw4dgSN5q8a7pjJhyzkm"
                ),
            },
            expected={"match": True},
            source="Aller-retour bcrypt (sel integre au hachage)",
        ),
    ),
)

ALGORITHMS = (SHA256, BCRYPT)
