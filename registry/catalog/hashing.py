"""Hachage et derivation de clefs."""

from __future__ import annotations

from db.models import (
    Argon2idInput,
    BcryptHashInput,
    BcryptVerifyInput,
    HmacLengthExtensionInput,
    KeyTextInput,
    Pbkdf2Input,
    ScryptInput,
    TextInput,
)
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
            input_model=BcryptHashInput,
            handler=lambda d: {
                "hash": hash_tool.hash_bcrypt(d.text, cost=d.cost),
                "cost": d.cost,
                "note": (
                    "Le hachage integre un sel tire au hasard. Le cout "
                    f"({d.cost}) fixe 2**{d.cost} tours : chaque unite double "
                    "le temps de calcul."
                ),
            },
            summary="Hacher un mot de passe (facteur de cout reglable)",
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

MD5 = Algorithm(
    slug="md5",
    name="MD5",
    family=Family.HASH,
    summary=(
        "Empreinte de 128 bits (RFC 1321). Des collisions pratiques sont "
        "connues depuis 2004 : deux messages differents peuvent partager la "
        "meme empreinte, calcules en quelques secondes sur un PC."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    year=1992,
    aliases=("empreinte", "digest", "casse"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {
                "hash": hash_tool.hash_md5(d.text),
                "warning": "MD5 est casse : des collisions sont produites en quelques secondes.",
            },
            summary="Calculer l'empreinte MD5 (a titre historique uniquement)",
            path="/md5",
        ),
    ),
    vectors=(
        TestVector(
            operation="hash",
            inputs={"text": ""},
            expected={"hash": "d41d8cd98f00b204e9800998ecf8427e"},
            source="RFC 1321, section A.5, chaine vide",
        ),
        TestVector(
            operation="hash",
            inputs={"text": "abc"},
            expected={"hash": "900150983cd24fb0d6963f7d28e17f72"},
            source="RFC 1321, section A.5, exemple 'abc'",
        ),
    ),
)

SHA1 = Algorithm(
    slug="sha1",
    name="SHA-1",
    family=Family.HASH,
    summary=(
        "Empreinte de 160 bits (FIPS 180-1 / RFC 3174). Casse en pratique en "
        "2017 par l'attaque SHAttered : deux PDF distincts, meme empreinte."
    ),
    maturity=Maturity.BROKEN,
    difficulty=3,
    year=1995,
    simulator="sha1",
    aliases=("shattered", "empreinte", "digest", "casse"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {
                "hash": hash_tool.hash_sha1(d.text),
                "warning": (
                    "SHA-1 est casse depuis 2017 (SHAttered) : ne plus "
                    "l'utiliser pour signer ou verifier une integrite."
                ),
            },
            summary="Calculer l'empreinte SHA-1 (a titre historique uniquement)",
            path="/sha1",
        ),
    ),
    vectors=(
        TestVector(
            operation="hash",
            inputs={"text": ""},
            expected={"hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            source="RFC 3174 / FIPS 180-1, empreinte de la chaine vide",
        ),
        TestVector(
            operation="hash",
            inputs={"text": "abc"},
            expected={"hash": "a9993e364706816aba3e25717850c26c9cd0d89d"},
            source="RFC 3174, section 7.3, exemple 1 ('abc')",
        ),
    ),
)

SHA3_256 = Algorithm(
    slug="sha3256",
    name="SHA-3-256",
    family=Family.HASH,
    summary=(
        "Empreinte de 256 bits par construction eponge Keccak (FIPS 202). "
        "Vainqueur du concours SHA-3 du NIST, structurellement independant "
        "de la famille Merkle-Damgard de SHA-1/SHA-256."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2015,
    aliases=("keccak", "eponge", "sponge"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {"hash": hash_tool.hash_sha3_256(d.text), "input": d.text},
            summary="Calculer l'empreinte SHA-3-256",
            path="/sha3256",
        ),
    ),
    vectors=(
        TestVector(
            operation="hash",
            inputs={"text": ""},
            expected={
                "hash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
            },
            source="NIST FIPS 202, empreinte de la chaine vide",
        ),
        TestVector(
            operation="hash",
            inputs={"text": "abc"},
            expected={
                "hash": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
            },
            source="NIST FIPS 202, exemple 'abc'",
        ),
    ),
)

BLAKE2B = Algorithm(
    slug="blake2b",
    name="BLAKE2b",
    family=Family.HASH,
    summary=(
        "Empreinte de 512 bits (RFC 7693), plus rapide que SHA-2/SHA-3 en "
        "logiciel sans compromis de securite connu. Utilise par WireGuard et "
        "comme fonction de hachage interne d'Argon2."
    ),
    maturity=Maturity.CURRENT,
    difficulty=3,
    year=2012,
    aliases=("blake2", "wireguard"),
    operations=(
        Operation(
            name="hash",
            input_model=TextInput,
            handler=lambda d: {"hash": hash_tool.hash_blake2b(d.text), "input": d.text},
            summary="Calculer l'empreinte BLAKE2b",
            path="/blake2b",
        ),
    ),
    vectors=(
        TestVector(
            operation="hash",
            inputs={"text": ""},
            expected={
                "hash": (
                    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                    "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
                )
            },
            source="RFC 7693, appendice A, empreinte de la chaine vide",
        ),
    ),
)

HMAC_SHA256 = Algorithm(
    slug="hmacsha256",
    name="HMAC-SHA256",
    family=Family.HASH,
    summary=(
        "Code d'authentification de message (RFC 2104 / FIPS 198-1). "
        "Contrairement a un hash nu, HMAC est immunise contre l'attaque par "
        "extension de longueur : c'est authentification, pas seulement "
        "integrite."
    ),
    maturity=Maturity.CURRENT,
    difficulty=3,
    year=1996,
    aliases=("mac", "authentification", "extension de longueur"),
    operations=(
        Operation(
            name="hmac",
            input_model=KeyTextInput,
            handler=lambda d: {
                "hmac": hash_tool.hmac_sha256(d.key, d.text),
                "note": (
                    "HMAC(K, m) = H((K^opad) || H((K^ipad) || m)) : le double "
                    "hachage empeche l'extension de longueur qui touche "
                    "SHA-256(K||m) tout seul."
                ),
            },
            summary="Calculer HMAC-SHA256(cle, message)",
            path="/hmacsha256",
        ),
        Operation(
            name="length-extension-demo",
            input_model=HmacLengthExtensionInput,
            handler=lambda d: hash_tool.demonstrate_length_extension_vulnerability(
                d.secret, d.message
            ),
            summary="Illustrer pourquoi un SHA-256 nu est vulnerable, contrairement a HMAC",
            path="/hmacsha256/length-extension-demo",
            length_field="message",
        ),
    ),
    vectors=(
        TestVector(
            operation="hmac",
            inputs={"key": "\x0b" * 20, "text": "Hi There"},
            expected={
                "hmac": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            },
            source="RFC 4231, section 4.2, cas de test 1",
        ),
        TestVector(
            operation="hmac",
            inputs={"key": "Jefe", "text": "what do ya want for nothing?"},
            expected={
                "hmac": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            },
            source="RFC 4231, section 4.3, cas de test 2",
        ),
    ),
)

PBKDF2 = Algorithm(
    slug="pbkdf2",
    name="PBKDF2",
    family=Family.HASH,
    summary=(
        "Derivation de cle par etirement CPU (RFC 8018) : applique HMAC en "
        "boucle pour ralentir la recherche exhaustive d'un mot de passe. "
        "Purement CPU, donc parallelisable sur GPU/ASIC — la limite que "
        "scrypt et Argon2 corrigent en exigeant aussi de la memoire."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2000,
    aliases=("pkcs5", "derivation de cle", "kdf", "etirement"),
    operations=(
        Operation(
            name="derive",
            input_model=Pbkdf2Input,
            handler=lambda d: {
                "derived_hex": hash_tool.pbkdf2_derive(
                    d.password, bytes.fromhex(d.salt_hex), d.iterations, d.dklen
                ).hex(),
                "iterations": d.iterations,
            },
            summary="Deriver une cle par PBKDF2-HMAC-SHA256",
            path="/pbkdf2",
            length_field="password",
        ),
    ),
    vectors=(
        # RFC 6070 (le KAT historique de PBKDF2) utilise HMAC-SHA1 ; ces
        # vecteurs verifient hashlib.pbkdf2_hmac directement dans les tests
        # unitaires. La route publique derive en SHA-256 (recommande
        # aujourd'hui) : le vecteur ci-dessous vient de RFC 7914 §11, qui
        # documente PBKDF2-HMAC-SHA256 precisement pour cet usage.
        TestVector(
            operation="derive",
            inputs={"password": "passwd", "salt_hex": "73616c74", "iterations": 1, "dklen": 64},
            expected={
                "derived_hex": (
                    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
                )
            },
            source="RFC 7914, section 11, PBKDF2-HMAC-SHA256 (P='passwd', S='salt', c=1)",
        ),
    ),
)

SCRYPT = Algorithm(
    slug="scrypt",
    name="scrypt",
    family=Family.HASH,
    summary=(
        "Derivation de cle a cout memoire ET CPU (RFC 7914) : exige une "
        "grande table temporaire en memoire, ce qui rend le parallelisme sur "
        "GPU/ASIC bien plus couteux qu'avec PBKDF2."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2009,
    aliases=("derivation de cle", "kdf", "memory-hard"),
    operations=(
        Operation(
            name="derive",
            input_model=ScryptInput,
            handler=lambda d: {
                "derived_hex": hash_tool.scrypt_derive(
                    d.password, bytes.fromhex(d.salt_hex), d.n, d.r, d.p, d.dklen
                ).hex(),
                "cost_parameters": {"n": d.n, "r": d.r, "p": d.p},
            },
            summary="Deriver une cle par scrypt",
            path="/scrypt",
            length_field="password",
        ),
    ),
    vectors=(
        TestVector(
            operation="derive",
            inputs={"password": "", "salt_hex": "", "n": 16, "r": 1, "p": 1, "dklen": 64},
            expected={
                "derived_hex": (
                    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede2144"
                    "2fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
                )
            },
            source="RFC 7914, section 12, cas de test 1 (P='', S='', N=16, r=1, p=1)",
        ),
    ),
)

ARGON2ID = Algorithm(
    slug="argon2id",
    name="Argon2id",
    family=Family.HASH,
    summary=(
        "Derivation de cle a cout memoire et CPU (RFC 9106), vainqueur du "
        "Password Hashing Competition (2015) et recommandation actuelle "
        "(OWASP) devant PBKDF2 et scrypt. Hybride Argon2i/Argon2d : resistant "
        "aux canaux auxiliaires ET au compromis temps-memoire."
    ),
    maturity=Maturity.CURRENT,
    difficulty=4,
    year=2015,
    aliases=("derivation de cle", "kdf", "memory-hard", "phc"),
    operations=(
        Operation(
            name="derive",
            input_model=Argon2idInput,
            handler=lambda d: {
                "derived_hex": hash_tool.argon2id_derive(
                    d.password,
                    bytes.fromhex(d.salt_hex),
                    d.time_cost,
                    d.memory_cost_kib,
                    d.parallelism,
                    d.dklen,
                ).hex(),
                "cost_parameters": {
                    "time_cost": d.time_cost,
                    "memory_cost_kib": d.memory_cost_kib,
                    "parallelism": d.parallelism,
                },
            },
            summary="Deriver une cle par Argon2id",
            path="/argon2id",
            length_field="password",
        ),
    ),
    vectors=(
        # RFC 9106 §5.3 publie un vecteur Argon2id, mais avec un secret et des
        # donnees associees en plus du mot de passe/sel — non exposes par la
        # route publique (elle ne prend que password/salt, comme PBKDF2 et
        # scrypt ci-dessus) ni par `argon2-cffi` sur ce systeme (la fonction
        # bas niveau disponible ici n'accepte pas ces deux parametres). Le
        # vecteur ci-dessous est calcule directement avec `argon2.low_level`
        # et fige : la CI verifie que l'implementation ne derive plus dans le
        # temps, meme methode deja utilisee pour ECDH/X25519 en Sprint 6.
        TestVector(
            operation="derive",
            inputs={
                "password": "password",
                "salt_hex": "736f6d6573616c743132333435363738",
                "time_cost": 2,
                "memory_cost_kib": 1024,
                "parallelism": 1,
                "dklen": 32,
            },
            expected={
                "derived_hex": (
                    "32c5dab38bfc007bc784bb11b476b39e83d5c2a6d81f008cba65cb333eb5dd77"
                )
            },
            source=(
                "Calcule avec argon2-cffi (argon2.low_level.hash_secret_raw, "
                "Type.ID, version 0x13) ; fige comme vecteur de non-regression "
                "faute de vecteur RFC 9106 reproductible sans secret/AD"
            ),
        ),
    ),
)

ALGORITHMS = (
    SHA256, SHA1, MD5, SHA3_256, BLAKE2B, HMAC_SHA256, PBKDF2, SCRYPT, ARGON2ID, BCRYPT,
)
