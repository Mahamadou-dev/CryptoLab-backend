"""Clef publique : RSA."""

from __future__ import annotations

from db.models import RsaDecryptInput, RsaEncryptInput
from registry.spec import Algorithm, Family, Maturity, Operation

RSA = Algorithm(
    slug="rsa",
    name="RSA-2048 (OAEP)",
    family=Family.ASYMMETRIC,
    summary=(
        "Chiffrement a clef publique fonde sur la difficulte de factoriser un "
        "produit de deux grands nombres premiers. Ce que Shor rendrait caduc."
    ),
    maturity=Maturity.CURRENT,
    difficulty=5,
    year=1977,
    aliases=("oaep", "clef publique"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _generate(),
            summary="Generer une paire de clefs RSA 2048 bits",
            method="GET",
            path="/rsa/generate-keys",
        ),
        Operation(
            name="encrypt",
            input_model=RsaEncryptInput,
            handler=lambda d: {"cipher_hex": _encrypt(d.text, d.public_key)},
            summary="Chiffrer avec une clef publique",
            description=(
                "OAEP reserve du remplissage : sur RSA-2048, il reste 214 octets "
                "utiles. RSA ne chiffre pas de gros messages — le monde reel "
                "l'emploie pour proteger une clef de session."
            ),
        ),
        Operation(
            name="decrypt",
            input_model=RsaDecryptInput,
            handler=lambda d: {"plain": _decrypt(d.cipher_hex, d.private_key)},
            summary="Dechiffrer avec une clef privee",
            length_field="cipher_hex",
        ),
    ),
    # Les vecteurs RSA officiels portent sur des primitives a remplissage fixe.
    # OAEP est probabiliste : la sortie change a chaque appel. La propriete
    # verifiee par les tests est donc l'aller-retour, pas une valeur figee.
)


# Import differe : PyCryptodome coute ~200 ms au chargement, et le catalogue est
# importe par des outils qui ne chiffrent rien (generation de documentation).
def _generate() -> dict:
    from utils import rsa_tool

    return rsa_tool.generate_rsa_keys()


def _encrypt(text: str, public_key: str) -> str:
    from utils import rsa_tool

    return rsa_tool.encrypt_rsa(text, public_key)


def _decrypt(cipher_hex: str, private_key: str) -> str:
    from utils import rsa_tool

    return rsa_tool.decrypt_rsa(cipher_hex, private_key)


ALGORITHMS = (RSA,)
