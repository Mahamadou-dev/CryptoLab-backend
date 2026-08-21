"""Symetrique moderne : AES (128/192/256), DES, 3DES, ChaCha20-Poly1305, RC4, modes d'operation."""

from __future__ import annotations

from db.models import (
    AesDecryptInput,
    AesVariantDecryptInput,
    ChaCha20DecryptInput,
    ChaCha20Input,
    DesDecryptInput,
    EcbPenguinInput,
    FinalistBlockHexInput,
    FinalistDecryptInput,
    KeyTextInput,
    ModesEncryptInput,
    PaddingOracleAttackInput,
    PaddingOracleEncryptInput,
    PaddingOracleQueryInput,
    Rc4HexInput,
    Rc4Input,
    TripleDesDecryptInput,
)
from registry.spec import Algorithm, Family, Maturity, Operation, TestVector
from utils import (
    aes_tool,
    chacha20_tool,
    des_tool,
    finalists_tool,
    modes_tool,
    padding_oracle,
    rc4_tool,
    tripledes_tool,
)


def _aes_variant(slug: str, name: str, key_size: int, year: int, summary_size: str) -> Algorithm:
    """
    Construit un algorithme AES-GCM pour une taille de cle donnee (16/24/32
    octets = AES-128/192/256). Les trois variantes partagent le meme code
    (`aes_tool`), seule la longueur de cle derivee change.
    """
    return Algorithm(
        slug=slug,
        name=name,
        family=Family.SYMMETRIC,
        summary=(
            f"AES en mode authentifie GCM, avec une cle de {summary_size}. Le "
            "chiffre porte un tag qui detecte toute alteration."
        ),
        maturity=Maturity.CURRENT,
        difficulty=4,
        year=year,
        simulator="aes" if key_size == 16 else None,
        aliases=("rijndael", "gcm", summary_size),
        operations=(
            Operation(
                name="encrypt",
                input_model=KeyTextInput,
                handler=lambda d, ks=key_size: aes_tool.encrypt_aes_gcm(d.text, d.key, key_size=ks),
                summary=f"Chiffrer en {name}",
                description=(
                    "Le nonce est tire au hasard a chaque appel : deux chiffrements "
                    "du meme texte avec la meme cle donnent des sorties differentes."
                ),
            ),
            Operation(
                name="decrypt",
                input_model=AesVariantDecryptInput,
                handler=lambda d, ks=key_size: {
                    "plain": aes_tool.decrypt_aes_gcm(
                        d.cipher_hex, d.key, d.nonce_hex, d.tag_hex, d.salt_hex, key_size=ks
                    )
                },
                summary="Dechiffrer et verifier le tag",
                length_field="cipher_hex",
            ),
        ),
        # Nonce aleatoire a chaque appel : pas de vecteur fixe possible sur
        # cette route (meme raison que pour AES-256, voir plus bas). Les
        # vecteurs FIPS-197 sont rejoues par le simulateur pas a pas (AES-128
        # uniquement, tests/test_simulators.py) et par modes_tool (ECB/CBC/CTR,
        # tests/test_modes.py).
    )


AES128 = _aes_variant("aes128", "AES-128-GCM", 16, 2001, "cle de 128 bits")
AES192 = _aes_variant("aes192", "AES-192-GCM", 24, 2001, "cle de 192 bits")

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
                "plain": aes_tool.decrypt_aes_gcm(
                    d.cipher_hex, d.key, d.nonce_hex, d.tag_hex, d.salt_hex
                )
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
            handler=lambda d: {
                "plain": des_tool.decrypt_des_cbc(d.cipher_hex, d.key, d.iv_hex, d.salt_hex)
            },
            summary="Dechiffrer un DES-CBC",
            length_field="cipher_hex",
        ),
    ),
    # Meme raison qu'AES : l'IV est aleatoire a chaque chiffrement.
)

TRIPLEDES = Algorithm(
    slug="tripledes",
    name="3DES-CBC",
    family=Family.SYMMETRIC,
    summary=(
        "DES applique trois fois (Encrypt-Decrypt-Encrypt, cle de 24 octets). "
        "Une attaque meet-in-the-middle sur le chiffrement double ramene sa "
        "securite effective a environ 2^112, pas 2^168 : c'est l'exemple "
        "classique montrant que composer un chiffre avec lui-meme n'additionne "
        "pas les bits de securite. Retire des nouveaux usages par le NIST "
        "(SP 800-131A Rev. 2)."
    ),
    maturity=Maturity.BROKEN,
    difficulty=4,
    year=1998,
    aliases=("3des", "tdea", "meet-in-the-middle"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: tripledes_tool.encrypt_3des_cbc(d.text, d.key),
            summary="Chiffrer en 3DES-CBC",
        ),
        Operation(
            name="decrypt",
            input_model=TripleDesDecryptInput,
            handler=lambda d: {
                "plain": tripledes_tool.decrypt_3des_cbc(d.cipher_hex, d.key, d.iv_hex, d.salt_hex)
            },
            summary="Dechiffrer un 3DES-CBC",
            length_field="cipher_hex",
        ),
    ),
    # IV aleatoire a chaque appel : pas de vecteur fixe sur cette route. La
    # correction du chiffre lui-meme est garantie par PyCryptodome (couche
    # production, non reimplementee) ; voir tests/test_tripledes.py pour le
    # test d'aller-retour et le rejet des cles degenerees.
)

CHACHA20 = Algorithm(
    slug="chacha20poly1305",
    name="ChaCha20-Poly1305",
    family=Family.SYMMETRIC,
    summary=(
        "Chiffrement de flot authentifie moderne (RFC 8439), standard de "
        "TLS 1.3. Alternative a AES-GCM qui ne depend d'aucune instruction "
        "materielle dediee : aussi rapide en logiciel pur."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2008,
    aliases=("chacha20", "poly1305", "rfc8439", "tls1.3"),
    operations=(
        Operation(
            name="encrypt",
            input_model=ChaCha20Input,
            handler=lambda d: chacha20_tool.encrypt_chacha20(d.text, d.key),
            summary="Chiffrer en ChaCha20-Poly1305",
            description=(
                "Le nonce (96 bits) est tire au hasard a chaque appel, comme "
                "pour AES-GCM."
            ),
        ),
        Operation(
            name="decrypt",
            input_model=ChaCha20DecryptInput,
            handler=lambda d: {
                "plain": chacha20_tool.decrypt_chacha20(d.cipher_hex, d.key, d.nonce_hex, d.salt_hex)
            },
            summary="Dechiffrer et verifier le tag Poly1305",
            length_field="cipher_hex",
        ),
    ),
    # Nonce aleatoire : pas de vecteur fixe sur cette route. Le vecteur
    # RFC 8439 §2.8.2 complet (cle, nonce, AAD et tag fixes) est rejoue
    # directement contre `chacha20_poly1305_raw` dans tests/test_chacha20.py.
)

RC4 = Algorithm(
    slug="rc4",
    name="RC4",
    family=Family.SYMMETRIC,
    summary=(
        "Chiffrement de flot omnipresent des annees 1990-2000 (SSL, WEP), "
        "retire de TLS en 2015 (RFC 7465) : un biais statistique dans ses "
        "premiers octets de flux de cle permet de recuperer du texte clair "
        "repete sur assez de sessions."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    year=1987,
    aliases=("arcfour", "casse", "flux"),
    operations=(
        Operation(
            name="encrypt",
            input_model=Rc4Input,
            handler=lambda d: rc4_tool.encrypt_rc4(d.text, d.key),
            summary="Chiffrer en RC4",
            description="Aucune derivation de cle : RC4 n'utilise que la cle brute (KSA + PRGA).",
        ),
        Operation(
            name="decrypt",
            input_model=Rc4Input,
            handler=lambda d: {"plain": rc4_tool.decrypt_rc4(
                rc4_tool.encrypt_rc4(d.text, d.key)["cipher_hex"], d.key
            )},
            summary="Demonstration : chiffrer puis dechiffrer (RC4 est involutif)",
            description=(
                "RC4 chiffre et dechiffre avec exactement la meme operation "
                "(XOR avec le flux de cle) : cette route illustre l'aller-retour "
                "plutot que de dechiffrer un texte fourni par l'appelant."
            ),
        ),
        Operation(
            name="keystream",
            input_model=Rc4HexInput,
            handler=lambda d: rc4_tool.rc4_hex(d.plaintext_hex, d.key_hex),
            summary="Chiffrer une entree hexadecimale (vecteurs RFC 6229)",
            path="/rc4/keystream",
            length_field="plaintext_hex",
        ),
    ),
    vectors=(
        TestVector(
            operation="keystream",
            inputs={"plaintext_hex": "00" * 16, "key_hex": "0102030405"},
            expected={"keystream_hex": "b2396305f03dc027ccc3524a0a1118a8"},
            source="RFC 6229 §2, vecteur de flux de cle pour la cle 40 bits 0102030405",
        ),
    ),
)


ECB_PENGUIN = Algorithm(
    slug="aesmodes",
    name="Modes d'operation AES",
    family=Family.SYMMETRIC,
    summary=(
        "ECB, CBC et CTR appliques au meme bloc de clair repete : ECB laisse "
        "le motif du clair visible dans le chiffre ('pingouin ECB'), CBC et "
        "CTR non. Cle et IV/nonce sont fournis explicitement — pedagogique "
        "uniquement, jamais fait ainsi en production."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=3,
    year=2001,
    aliases=("ecb", "cbc", "ctr", "pingouin", "modes"),
    operations=(
        Operation(
            name="encrypt-ecb",
            input_model=ModesEncryptInput,
            handler=lambda d: modes_tool.encrypt_ecb(d.key_hex, d.plaintext_hex),
            summary="Chiffrer en ECB (cle et clair en hexadecimal)",
            length_field="plaintext_hex",
        ),
        Operation(
            name="encrypt-cbc",
            input_model=ModesEncryptInput,
            handler=lambda d: modes_tool.encrypt_cbc(d.key_hex, d.plaintext_hex, d.iv_hex),
            summary="Chiffrer en CBC (cle, IV et clair en hexadecimal)",
            length_field="plaintext_hex",
        ),
        Operation(
            name="encrypt-ctr",
            input_model=ModesEncryptInput,
            handler=lambda d: modes_tool.encrypt_ctr(d.key_hex, d.plaintext_hex, d.iv_hex),
            summary="Chiffrer en CTR (cle, compteur initial et clair en hexadecimal)",
            length_field="plaintext_hex",
        ),
        Operation(
            name="penguin-demo",
            input_model=EcbPenguinInput,
            handler=lambda d: modes_tool.ecb_penguin_demo(d.key_hex, d.block_hex, d.repeats),
            summary="Repeter un bloc et comparer ECB/CBC/CTR (le pingouin ECB)",
            length_field="block_hex",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt-ecb",
            inputs={
                "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
                "plaintext_hex": (
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710"
                ),
            },
            expected={
                "cipher_hex": (
                    "3ad77bb40d7a3660a89ecaf32466ef97"
                    "f5d3d58503b9699de785895a96fdbaaf"
                    "43b1cd7f598ece23881b00e3ed030688"
                    "7b0c785e27e8ad3f8223207104725dd4"
                )
            },
            source="NIST SP 800-38A, annexe F.1.1 (ECB-AES128.Encrypt)",
        ),
        TestVector(
            operation="encrypt-cbc",
            inputs={
                "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv_hex": "000102030405060708090a0b0c0d0e0f",
                "plaintext_hex": (
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710"
                ),
            },
            expected={
                "cipher_hex": (
                    "7649abac8119b246cee98e9b12e9197d"
                    "5086cb9b507219ee95db113a917678b2"
                    "73bed6b8e3c1743b7116e69e22229516"
                    "3ff1caa1681fac09120eca307586e1a7"
                )
            },
            source="NIST SP 800-38A, annexe F.2.1 (CBC-AES128.Encrypt)",
        ),
        TestVector(
            operation="encrypt-ctr",
            inputs={
                "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv_hex": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "plaintext_hex": (
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710"
                ),
            },
            expected={
                "cipher_hex": (
                    "874d6191b620e3261bef6864990db6ce"
                    "9806f66b7970fdff8617187bb9fffdff"
                    "5ae4df3edbd5d35e5b4f09020db03eab"
                    "1e031dda2fbe03d1792170a0f3009cee"
                )
            },
            source="NIST SP 800-38A, annexe F.5.1 (CTR-AES128.Encrypt)",
        ),
    ),
)


BLOWFISH = Algorithm(
    slug="blowfish",
    name="Blowfish-CBC",
    family=Family.SYMMETRIC,
    summary=(
        "Chiffre par blocs concu par Bruce Schneier en 1993, libre de droits, "
        "predecesseur de Twofish. Jamais casse sur cle pleine longueur, mais "
        "son bloc de 64 bits le rend vulnerable a l'attaque par anniversaire "
        "Sweet32 au-dela de quelques Go sous la meme cle — la raison de sa "
        "mise a l'ecart au profit d'AES (bloc de 128 bits), pas une faiblesse "
        "de son chiffrement lui-meme."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=3,
    year=1993,
    aliases=("schneier", "twofish", "sweet32", "finaliste"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: finalists_tool.encrypt_blowfish_cbc(d.text, d.key),
            summary="Chiffrer en Blowfish-CBC",
        ),
        Operation(
            name="decrypt",
            input_model=FinalistDecryptInput,
            handler=lambda d: {
                "plain": finalists_tool.decrypt_blowfish_cbc(d.cipher_hex, d.key, d.iv_hex, d.salt_hex)
            },
            summary="Dechiffrer un Blowfish-CBC",
            length_field="cipher_hex",
        ),
        Operation(
            name="ecb-block",
            input_model=FinalistBlockHexInput,
            handler=lambda d: finalists_tool.blowfish_ecb_block_hex(d.key_hex, d.plaintext_hex),
            summary="Chiffrer un bloc de 8 octets en Blowfish-ECB (vecteurs officiels)",
            path="/blowfish/ecb-block",
            length_field="plaintext_hex",
        ),
    ),
    vectors=(
        TestVector(
            operation="ecb-block",
            inputs={"key_hex": "0000000000000000", "plaintext_hex": "0000000000000000"},
            expected={"cipher_hex": "4ef997456198dd78"},
            source="Bruce Schneier, vecteurs de test Blowfish officiels (cle nulle)",
        ),
        TestVector(
            operation="ecb-block",
            inputs={"key_hex": "ffffffffffffffff", "plaintext_hex": "ffffffffffffffff"},
            expected={"cipher_hex": "51866fd5b85ecb8a"},
            source="Bruce Schneier, vecteurs de test Blowfish officiels (cle a un)",
        ),
    ),
)


CAMELLIA = Algorithm(
    slug="camellia",
    name="Camellia-128-CBC",
    family=Family.SYMMETRIC,
    summary=(
        "Chiffre par blocs co-developpe par Mitsubishi Electric et NTT (2000), "
        "retenu par CRYPTREC, l'ISO/IEC 18033-3 et l'IETF (RFC 3713) comme "
        "alternative a AES a securite comparable. Encore largement utilise au "
        "Japon (TLS, IPsec)."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2000,
    aliases=("ntt", "mitsubishi", "iso18033", "japon"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: finalists_tool.encrypt_camellia_cbc(d.text, d.key),
            summary="Chiffrer en Camellia-128-CBC",
        ),
        Operation(
            name="decrypt",
            input_model=FinalistDecryptInput,
            handler=lambda d: {
                "plain": finalists_tool.decrypt_camellia_cbc(d.cipher_hex, d.key, d.iv_hex, d.salt_hex)
            },
            summary="Dechiffrer un Camellia-128-CBC",
            length_field="cipher_hex",
        ),
        Operation(
            name="ecb-block",
            input_model=FinalistBlockHexInput,
            handler=lambda d: finalists_tool.camellia_ecb_block_hex(d.key_hex, d.plaintext_hex),
            summary="Chiffrer un bloc de 16 octets en Camellia-ECB (vecteur officiel)",
            path="/camellia/ecb-block",
            length_field="plaintext_hex",
        ),
    ),
    vectors=(
        TestVector(
            operation="ecb-block",
            inputs={
                "key_hex": "0123456789abcdeffedcba9876543210",
                "plaintext_hex": "0123456789abcdeffedcba9876543210",
            },
            expected={"cipher_hex": "67673138549669730857065648eabe43"},
            source="RFC 3713, annexe A (vecteur de test Camellia-128 officiel NTT/Mitsubishi)",
        ),
    ),
    # Twofish et Serpent (finalistes retenus du concours AES, tous deux battus
    # par Rijndael en 2000) restent hors de ce catalogue : ni PyCryptodome ni
    # pyca/cryptography ne les exposent, et l'environnement n'a pas de
    # dependance simple sans compilation native (voir utils/finalists_tool.py
    # et SPRINTS.md Sprint 5).
)


PADDING_ORACLE = Algorithm(
    slug="paddingoracle",
    name="Oracle de bourrage PKCS#7",
    family=Family.SYMMETRIC,
    summary=(
        "AES-CBC + PKCS#7 avec cle et IV fournis en clair : un labo d'attaque "
        "qui casse le chiffrement sans jamais connaitre la cle, en n'exploitant "
        "que la reponse vrai/faux d'un serveur sur la validite du bourrage "
        "(attaque de Vaudenay, 2002). C'est pour empecher exactement cette "
        "fuite que les modes authentifies (GCM, Poly1305) existent."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=5,
    year=2002,
    aliases=("vaudenay", "cbc", "pkcs7", "oracle"),
    operations=(
        Operation(
            name="encrypt",
            input_model=PaddingOracleEncryptInput,
            handler=lambda d: padding_oracle.encrypt_for_oracle(d.key_hex, d.iv_hex, d.plaintext),
            summary="Chiffrer un texte en AES-CBC + PKCS#7 (cle et IV en clair)",
            length_field="plaintext",
        ),
        Operation(
            name="oracle-query",
            input_model=PaddingOracleQueryInput,
            handler=lambda d: padding_oracle.oracle_query(d.key_hex, d.iv_hex, d.cipher_hex),
            summary="Interroger l'oracle : ce couple (IV, chiffre) a-t-il un bourrage valide ?",
            path="/paddingoracle/oracle-query",
            length_field="cipher_hex",
        ),
        Operation(
            name="attack",
            input_model=PaddingOracleAttackInput,
            handler=lambda d: padding_oracle.padding_oracle_attack(d.key_hex, d.iv_hex, d.cipher_hex),
            summary="Dechiffrer entierement via l'oracle de bourrage, sans la cle",
            path="/paddingoracle/attack",
            length_field="cipher_hex",
        ),
    ),
    # Pas de vecteur NIST/RFC (il n'existe pas de reference officielle pour
    # une demonstration d'attaque), mais `encrypt` est entierement
    # deterministe (cle et IV fournis en clair par l'appelant, sans tirage
    # aleatoire) : un vecteur genere localement, verrouille ici, sert de
    # garde non-regression. La propriete cryptographique verifiee ailleurs
    # (tests/test_padding_oracle.py) est l'invariant chiffrer -> attaquer
    # sans la cle -> retomber exactement sur le clair d'origine.
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={
                "key_hex": "000102030405060708090a0b0c0d0e0f",
                "iv_hex": "101112131415161718191a1b1c1d1e1f",
                "plaintext": "Attaque",
            },
            expected={"cipher_hex": "b4e262df6ef2d4d08dc50af8c4d9aed3", "block_count": 1},
            source="Vecteur local (module deterministe, cle et IV fournis en clair) : "
            "verrouille la sortie contre une regression, ne pretend pas etre un "
            "vecteur NIST/RFC.",
        ),
    ),
)


ALGORITHMS = (
    AES128, AES192, AES, DES, TRIPLEDES, BLOWFISH, CAMELLIA, CHACHA20, RC4,
    ECB_PENGUIN, PADDING_ORACLE,
)
