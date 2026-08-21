"""Clef publique : RSA, RSA petits nombres, signatures RSA, Diffie-Hellman, ECDH, ECC."""

from __future__ import annotations

from db.models import (
    DhSmallNumbersInput,
    EccPointAddInput,
    EccScalarMultiplyInput,
    EcdhExchangeInput,
    RsaDecryptInput,
    RsaEncryptInput,
    RsaSignInput,
    RsaVerifyInput,
    SmallRsaDecryptInput,
    SmallRsaEncryptInput,
    SmallRsaKeygenInput,
    SmallRsaSignInput,
    SmallRsaVerifyInput,
)
from registry.spec import Algorithm, Family, Maturity, Operation, TestVector

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


RSA_SMALL = Algorithm(
    slug="rsasmall",
    name="RSA (petits nombres)",
    family=Family.ASYMMETRIC,
    summary=(
        "Le meme RSA que ci-dessus, mais p, q, phi(n) et d sont calcules a la "
        "main sur de petits nombres premiers fournis par l'appelant : ce qui "
        "se cache derriere `RSA.generate(2048)`. Ne chiffre qu'un entier plus "
        "petit que n, jamais un texte reel."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=3,
    year=1977,
    aliases=("euclide", "phi", "totient", "petit rsa"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=SmallRsaKeygenInput,
            handler=lambda d: _small_rsa_keygen(d.p, d.q, d.e),
            summary="Calculer n, phi(n), e et d a partir de deux petits premiers",
        ),
        Operation(
            name="encrypt",
            input_model=SmallRsaEncryptInput,
            handler=lambda d: _small_rsa_encrypt(d.message, d.e, d.n),
            summary="Chiffrer un entier m < n : c = m^e mod n",
        ),
        Operation(
            name="decrypt",
            input_model=SmallRsaDecryptInput,
            handler=lambda d: _small_rsa_decrypt(d.cipher, d.d, d.n),
            summary="Dechiffrer : m = c^d mod n",
        ),
        Operation(
            name="sign",
            input_model=SmallRsaSignInput,
            handler=lambda d: _small_rsa_sign(d.message, d.d, d.n),
            summary="Signer avec la cle PRIVEE : s = m^d mod n",
        ),
        Operation(
            name="verify",
            input_model=SmallRsaVerifyInput,
            handler=lambda d: _small_rsa_verify(d.message, d.signature, d.e, d.n),
            summary="Verifier avec la cle PUBLIQUE : m == s^e mod n",
        ),
    ),
    vectors=(
        TestVector(
            operation="generate-keys",
            inputs={"p": 61, "q": 53, "e": 17},
            expected={"n": 3233, "phi": 3120, "e": 17, "d": 2753},
            source="Wikipedia, exemple pedagogique RSA canonique (p=61, q=53, e=17)",
        ),
        TestVector(
            operation="encrypt",
            inputs={"message": 65, "e": 17, "n": 3233},
            expected={"cipher": 2790},
            source="Meme exemple, chiffrement de m=65",
        ),
        TestVector(
            operation="decrypt",
            inputs={"cipher": 2790, "d": 2753, "n": 3233},
            expected={"plain": 65},
            source="Meme exemple, dechiffrement du chiffre 2790",
        ),
    ),
)


def _small_rsa_keygen(p: int, q: int, e: int) -> dict:
    from utils import rsa_small

    keys = rsa_small.generate_small_rsa(p, q, e)
    return {"p": keys.p, "q": keys.q, "n": keys.n, "phi": keys.phi, "e": keys.e, "d": keys.d, "steps": keys.steps}


def _small_rsa_encrypt(message: int, e: int, n: int) -> dict:
    from utils import rsa_small

    return rsa_small.encrypt_small_rsa(message, e, n)


def _small_rsa_decrypt(cipher: int, d: int, n: int) -> dict:
    from utils import rsa_small

    return rsa_small.decrypt_small_rsa(cipher, d, n)


def _small_rsa_sign(message: int, d: int, n: int) -> dict:
    from utils import rsa_small

    return rsa_small.sign_small_rsa(message, d, n)


def _small_rsa_verify(message: int, signature: int, e: int, n: int) -> dict:
    from utils import rsa_small

    return rsa_small.verify_small_rsa(message, signature, e, n)


RSA_SIGNATURE = Algorithm(
    slug="rsasignature",
    name="Signature RSA (PKCS#1 v1.5 et PSS)",
    family=Family.ASYMMETRIC,
    summary=(
        "Signer n'est pas chiffrer : la cle PRIVEE signe, la cle PUBLIQUE "
        "verifie — l'inverse exact du chiffrement RSA. PKCS#1 v1.5 est "
        "deterministe, RSA-PSS ajoute un sel aleatoire (RFC 8017) et est "
        "recommande pour les nouveaux usages."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=1998,
    aliases=("pss", "pkcs1", "signature numerique"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _rsa_sig_generate(),
            summary="Generer une paire de cles RSA-2048 dediee a la signature",
            method="GET",
            path="/rsasignature/generate-keys",
        ),
        Operation(
            name="sign-pkcs1v15",
            input_model=RsaSignInput,
            handler=lambda d: _rsa_sig_sign_pkcs1v15(d.message, d.private_key),
            summary="Signer avec PKCS#1 v1.5 (deterministe)",
        ),
        Operation(
            name="verify-pkcs1v15",
            input_model=RsaVerifyInput,
            handler=lambda d: _rsa_sig_verify_pkcs1v15(d.message, d.signature_hex, d.public_key),
            summary="Verifier une signature PKCS#1 v1.5",
        ),
        Operation(
            name="sign-pss",
            input_model=RsaSignInput,
            handler=lambda d: _rsa_sig_sign_pss(d.message, d.private_key),
            summary="Signer avec RSA-PSS (probabiliste, sel aleatoire)",
        ),
        Operation(
            name="verify-pss",
            input_model=RsaVerifyInput,
            handler=lambda d: _rsa_sig_verify_pss(d.message, d.signature_hex, d.public_key),
            summary="Verifier une signature RSA-PSS",
        ),
    ),
    # PKCS#1 v1.5 est deterministe mais depend d'une cle RSA-2048 generee a
    # chaque test (pas de cle fixe publiee comme vecteur officiel de ce
    # niveau) ; PSS est probabiliste par construction. La propriete verifiee
    # (tests/test_rsa_signature.py) est signer -> verifier -> valide, et
    # signer -> alterer un octet -> verifier -> invalide.
)


def _rsa_sig_generate() -> dict:
    from utils import rsa_signature_tool

    return rsa_signature_tool.generate_rsa_signing_keys()


def _rsa_sig_sign_pkcs1v15(message: str, private_key: str) -> dict:
    from utils import rsa_signature_tool

    return rsa_signature_tool.sign_rsa_pkcs1v15(message, private_key)


def _rsa_sig_verify_pkcs1v15(message: str, signature_hex: str, public_key: str) -> dict:
    from utils import rsa_signature_tool

    return rsa_signature_tool.verify_rsa_pkcs1v15(message, signature_hex, public_key)


def _rsa_sig_sign_pss(message: str, private_key: str) -> dict:
    from utils import rsa_signature_tool

    return rsa_signature_tool.sign_rsa_pss(message, private_key)


def _rsa_sig_verify_pss(message: str, signature_hex: str, public_key: str) -> dict:
    from utils import rsa_signature_tool

    return rsa_signature_tool.verify_rsa_pss(message, signature_hex, public_key)


DIFFIE_HELLMAN = Algorithm(
    slug="diffiehellman",
    name="Diffie-Hellman",
    family=Family.ASYMMETRIC,
    summary=(
        "Le secret partage sans secret transmis : Alice et Bob echangent des "
        "valeurs publiques calculees a partir d'un secret que chacun garde "
        "pour soi, et retombent sur le meme nombre sans qu'Eve, qui observe "
        "tout le canal, ne puisse le reconstruire (probleme du logarithme "
        "discret)."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=3,
    year=1976,
    aliases=("dh", "logarithme discret", "echange de cles"),
    operations=(
        Operation(
            name="exchange",
            input_model=DhSmallNumbersInput,
            handler=lambda d: _dh_exchange(d.p, d.g, d.a, d.b),
            summary="Simuler un echange DH complet (Alice, Bob, ce qu'Eve voit)",
        ),
    ),
    vectors=(
        TestVector(
            operation="exchange",
            inputs={"p": 23, "g": 5, "a": 6, "b": 15},
            expected={"public_a": 8, "public_b": 19, "shared_secret": 2, "secrets_match": True},
            source="Exemple textbook classique (p=23, g=5) — cf. Wikipedia, Diffie-Hellman key exchange",
        ),
    ),
)


def _dh_exchange(p: int, g: int, a: int, b: int) -> dict:
    from utils import dh_tool

    return dh_tool.dh_small_numbers(p, g, a, b)


ECDH = Algorithm(
    slug="ecdh",
    name="ECDH (X25519)",
    family=Family.ASYMMETRIC,
    summary=(
        "Diffie-Hellman sur une courbe elliptique : X25519 (RFC 7748), utilise "
        "par TLS 1.3, Signal et WireGuard. Meme principe que Diffie-Hellman "
        "classique, mais le groupe est celui des points de Curve25519, bien "
        "plus dur a attaquer a taille de cle egale."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2006,
    aliases=("x25519", "curve25519", "rfc7748"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _ecdh_generate(),
            summary="Generer une paire de cles X25519",
            method="GET",
            path="/ecdh/generate-keys",
        ),
        Operation(
            name="exchange",
            input_model=EcdhExchangeInput,
            handler=lambda d: _ecdh_exchange(d.private_hex, d.peer_public_hex),
            summary="Calculer le secret partage a partir d'une cle privee et d'une cle publique paire",
        ),
    ),
    vectors=(
        TestVector(
            operation="exchange",
            inputs={
                "private_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "peer_public_hex": "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
            },
            expected={"shared_secret_hex": "4274a32e953acb8314d0f09bcbcb5193c5ef799ddcd0036f8c4682e5801dac73"},
            # Pas de vecteur RFC 7748 §5.2/§6.1 recopie ici : les chaines memorisees
            # ne tombaient pas sur 32 octets exacts et republier un vecteur
            # "officiel" incorrect est pire que de ne pas en avoir. Vecteur
            # reproductible a la place : cle privee d'Alice = octets 0x00..0x1f,
            # cle publique paire = X25519(octets 0x01..0x20, base point 9) —
            # verifie par round-trip (exchange(Alice, pub(Bob)) ==
            # exchange(Bob, pub(Alice))) dans tests/test_asymmetric_sprint6.py.
            source="Vecteur reproductible (cles fixes, non aleatoires), verifie par round-trip Alice<->Bob",
        ),
    ),
)


def _ecdh_generate() -> dict:
    from utils import dh_tool

    return dh_tool.ecdh_x25519_generate()


def _ecdh_exchange(private_hex: str, peer_public_hex: str) -> dict:
    from utils import dh_tool

    return dh_tool.ecdh_x25519_exchange(private_hex, peer_public_hex)


ECC = Algorithm(
    slug="ecc",
    name="Courbe elliptique (secp256k1)",
    family=Family.ASYMMETRIC,
    summary=(
        "Addition et multiplication scalaire de points sur secp256k1 (la "
        "courbe de Bitcoin et Ethereum), en Python pur : la loi de groupe qui "
        "fonde ECDH, ECDSA et Ed25519. Point + Point = Point, calcule "
        "geometriquement via la droite (ou la tangente) qui les relie."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=5,
    year=1985,
    aliases=("secp256k1", "bitcoin", "point elliptique", "weierstrass"),
    operations=(
        Operation(
            name="point-add",
            input_model=EccPointAddInput,
            handler=lambda d: _ecc_add(d.x1, d.y1, d.x2, d.y2),
            summary="Additionner deux points de secp256k1",
        ),
        Operation(
            name="scalar-multiply",
            input_model=EccScalarMultiplyInput,
            handler=lambda d: _ecc_scalar_multiply(d.k, d.x, d.y),
            summary="Calculer k*P (doublement-et-addition)",
        ),
    ),
    vectors=(
        TestVector(
            operation="scalar-multiply",
            inputs={
                "k": 2,
                "x": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                "y": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            },
            expected={
                "result": {
                    "x": 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
                    "y": 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
                }
            },
            source="SEC 2 v2 §2.4.1 : 2*G sur secp256k1, ou G est le point generateur standard",
        ),
    ),
)


def _ecc_add(x1: int, y1: int, x2: int, y2: int) -> dict:
    from utils import ecc_tool

    return ecc_tool.secp256k1_point_add(x1, y1, x2, y2)


def _ecc_scalar_multiply(k: int, x: int, y: int) -> dict:
    from utils import ecc_tool

    return ecc_tool.secp256k1_scalar_multiply(k, x, y)


ALGORITHMS = (RSA, RSA_SMALL, RSA_SIGNATURE, DIFFIE_HELLMAN, ECDH, ECC)
