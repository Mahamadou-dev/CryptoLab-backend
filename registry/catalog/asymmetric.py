"""Clef publique : RSA, RSA petits nombres, signatures RSA/ECDSA/Ed25519, Diffie-Hellman, ECDH, ECC."""

from __future__ import annotations

from db.models import (
    DhSmallNumbersInput,
    DsaSignInput,
    DsaVerifyInput,
    EccPointAddInput,
    EccScalarMultiplyInput,
    EcdhExchangeInput,
    EcdsaSignInput,
    EcdsaVerifyInput,
    Ed25519SignInput,
    Ed25519VerifyInput,
    ElGamalDecryptInput,
    ElGamalEncryptInput,
    ElGamalKeygenInput,
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


ECDSA = Algorithm(
    slug="ecdsa",
    name="ECDSA (secp256k1)",
    family=Family.ASYMMETRIC,
    summary=(
        "Signature numerique sur la courbe de Bitcoin/Ethereum. Probabiliste : "
        "un nonce aleatoire different a chaque signature. Un nonce reutilise ou "
        "previsible expose la cle privee entiere — la cause reelle du vol de "
        "cles de signature de la PS3 (fail0verflow, 2010) et de plusieurs vols "
        "de bitcoins."
    ),
    maturity=Maturity.CURRENT,
    difficulty=5,
    year=1992,
    aliases=("secp256k1", "bitcoin", "nonce", "signature numerique"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _ecdsa_generate(),
            summary="Generer une paire de cles ECDSA/secp256k1",
            method="GET",
            path="/ecdsa/generate-keys",
        ),
        Operation(
            name="sign",
            input_model=EcdsaSignInput,
            handler=lambda d: _ecdsa_sign(d.message, d.private_key),
            summary="Signer avec ECDSA/secp256k1 + SHA-256 (nonce aleatoire)",
            length_field="message",
        ),
        Operation(
            name="verify",
            input_model=EcdsaVerifyInput,
            handler=lambda d: _ecdsa_verify(d.message, d.signature_hex, d.public_key),
            summary="Verifier une signature ECDSA",
            length_field="message",
        ),
    ),
    # Nonce aleatoire a chaque signature (par construction, comme AES-GCM) :
    # pas de vecteur fixe possible sur `sign`. Propriete verifiee : signer ->
    # verifier -> valide, message altere -> invalide (tests/test_ecdsa_ed25519.py).
)


ED25519 = Algorithm(
    slug="ed25519",
    name="Ed25519",
    family=Family.ASYMMETRIC,
    summary=(
        "Signature deterministe sur Curve25519 (RFC 8032, forme Twisted "
        "Edwards) : pas de nonce a proteger, contrairement a ECDSA — signer "
        "deux fois le meme message avec la meme cle donne toujours la meme "
        "signature. Utilisee par SSH, Signal, et de plus en plus TLS."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2011,
    aliases=("rfc8032", "curve25519", "ssh", "signal", "deterministe"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _ed25519_generate(),
            summary="Generer une paire de cles Ed25519",
            method="GET",
            path="/ed25519/generate-keys",
        ),
        Operation(
            name="sign",
            input_model=Ed25519SignInput,
            handler=lambda d: _ed25519_sign(d.message_hex, d.private_hex),
            summary="Signer avec Ed25519 (deterministe, message et cle en hexadecimal)",
            path="/ed25519/sign",
            length_field="message_hex",
        ),
        Operation(
            name="verify",
            input_model=Ed25519VerifyInput,
            handler=lambda d: _ed25519_verify(d.message_hex, d.signature_hex, d.public_hex),
            summary="Verifier une signature Ed25519",
            path="/ed25519/verify",
            length_field="message_hex",
        ),
    ),
    # Cles generees aleatoirement (`generate-keys`) : pas de vecteur fixe sur
    # cette route. `sign` est deterministe une fois la cle fixee, mais aucun
    # vecteur RFC 8032 fige n'est publie ici (le risque de retranscrire un
    # octet errone d'un vecteur a 64 octets l'emporte sur son interet — meme
    # decision que pour ECDH en Sprint 6, voir SPRINTS.md). La propriete
    # verifiee est signer -> verifier -> valide, signer deux fois -> memes
    # octets, message altere -> invalide.
)


DSA = Algorithm(
    slug="dsa",
    name="DSA",
    family=Family.ASYMMETRIC,
    summary=(
        "Signature numerique fondee sur le logarithme discret dans (Z/pZ)*, "
        "comme Diffie-Hellman et ElGamal — mais utilisee pour signer, pas pour "
        "chiffrer ni echanger une cle : la meme famille mathematique au service "
        "de trois usages distincts. Standard federal americain de 1994 a 2023, "
        "aujourd'hui retire au profit d'ECDSA/EdDSA (FIPS 186-5)."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=4,
    year=1991,
    aliases=("fips186", "digital signature algorithm", "deprecie"),
    operations=(
        Operation(
            name="generate-keys",
            input_model=None,
            handler=lambda _: _dsa_generate(),
            summary="Generer une paire de cles DSA (2048 bits)",
            method="GET",
            path="/dsa/generate-keys",
        ),
        Operation(
            name="sign",
            input_model=DsaSignInput,
            handler=lambda d: _dsa_sign(d.message, d.private_key),
            summary="Signer avec DSA + SHA-256 (nonce aleatoire)",
            length_field="message",
        ),
        Operation(
            name="verify",
            input_model=DsaVerifyInput,
            handler=lambda d: _dsa_verify(d.message, d.signature_hex, d.public_key),
            summary="Verifier une signature DSA",
            length_field="message",
        ),
    ),
    # Nonce aleatoire a chaque signature (probabiliste, comme ECDSA) : pas de
    # vecteur fixe possible sur `sign`. Propriete verifiee : signer -> verifier
    # -> valide, message altere -> invalide (tests/test_asymmetric_sprint6b.py).
)


def _dsa_generate() -> dict:
    from utils import dsa_tool

    return dsa_tool.generate_dsa_keys()


def _dsa_sign(message: str, private_key: str) -> dict:
    from utils import dsa_tool

    return dsa_tool.sign_dsa(message, private_key)


def _dsa_verify(message: str, signature_hex: str, public_key: str) -> dict:
    from utils import dsa_tool

    return dsa_tool.verify_dsa(message, signature_hex, public_key)


ELGAMAL = Algorithm(
    slug="elgamal",
    name="ElGamal",
    family=Family.ASYMMETRIC,
    summary=(
        "Chiffrement a clef publique fonde directement sur le logarithme "
        "discret (contrairement a RSA, fonde sur la factorisation). "
        "Probabiliste : un nonce ephemere k different a chaque chiffrement "
        "produit un texte chiffre different pour le meme message clair. "
        "Meme squelette mathematique que Diffie-Hellman ; DSA en derive pour "
        "signer plutot que chiffrer."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=4,
    year=1985,
    aliases=("logarithme discret", "cramer-shoup", "petits nombres"),
    operations=(
        Operation(
            name="keygen",
            input_model=ElGamalKeygenInput,
            handler=lambda d: _elgamal_keygen(d.p, d.g, d.x),
            summary="Generer une paire de cles ElGamal 'petits nombres' (p, g, x fournis)",
        ),
        Operation(
            name="encrypt",
            input_model=ElGamalEncryptInput,
            handler=lambda d: _elgamal_encrypt(d.p, d.g, d.y, d.m, d.k),
            summary="Chiffrer un entier m avec la cle publique (p, g, y)",
        ),
        Operation(
            name="decrypt",
            input_model=ElGamalDecryptInput,
            handler=lambda d: _elgamal_decrypt(d.p, d.x, d.c1, d.c2),
            summary="Dechiffrer (c1, c2) avec la cle privee x",
        ),
    ),
    vectors=(
        TestVector(
            operation="keygen",
            inputs={"p": 23, "g": 5, "x": 6},
            expected={"p": 23, "g": 5, "x": 6, "y": 8},
            source="p=23, g=5 (meme groupe que le vecteur Diffie-Hellman textbook) : y = 5^6 mod 23 = 8",
        ),
        TestVector(
            operation="encrypt",
            inputs={"p": 23, "g": 5, "y": 8, "m": 10, "k": 3},
            expected={"c1": 10, "c2": 14},
            source="k=3 fixe pour un vecteur reproductible : c1 = 5^3 mod 23 = 10, c2 = 10*8^3 mod 23 = 10*6 mod 23 = 14",
        ),
        TestVector(
            operation="decrypt",
            inputs={"p": 23, "x": 6, "c1": 10, "c2": 14},
            expected={"m": 10},
            source="Round-trip du vecteur encrypt ci-dessus : dechiffrer (10, 14) avec x=6 doit redonner m=10",
        ),
    ),
)


def _elgamal_keygen(p: int, g: int, x: int) -> dict:
    from utils import elgamal_tool

    return elgamal_tool.elgamal_keygen(p, g, x)


def _elgamal_encrypt(p: int, g: int, y: int, m: int, k: int | None) -> dict:
    from utils import elgamal_tool

    return elgamal_tool.elgamal_encrypt(p, g, y, m, k)


def _elgamal_decrypt(p: int, x: int, c1: int, c2: int) -> dict:
    from utils import elgamal_tool

    return elgamal_tool.elgamal_decrypt(p, x, c1, c2)


ALGORITHMS = (
    RSA,
    RSA_SMALL,
    RSA_SIGNATURE,
    DIFFIE_HELLMAN,
    ECDH,
    ECC,
    ECDSA,
    ED25519,
    DSA,
    ELGAMAL,
)


def _ecdsa_generate() -> dict:
    from utils import signature_tool

    return signature_tool.generate_ecdsa_keys()


def _ecdsa_sign(message: str, private_key: str) -> dict:
    from utils import signature_tool

    return signature_tool.sign_ecdsa(message, private_key)


def _ecdsa_verify(message: str, signature_hex: str, public_key: str) -> dict:
    from utils import signature_tool

    return signature_tool.verify_ecdsa(message, signature_hex, public_key)


def _ed25519_generate() -> dict:
    from utils import signature_tool

    return signature_tool.generate_ed25519_keys()


def _ed25519_sign(message_hex: str, private_hex: str) -> dict:
    from utils import signature_tool

    return signature_tool.sign_ed25519(message_hex, private_hex)


def _ed25519_verify(message_hex: str, signature_hex: str, public_hex: str) -> dict:
    from utils import signature_tool

    return signature_tool.verify_ed25519(message_hex, signature_hex, public_hex)
