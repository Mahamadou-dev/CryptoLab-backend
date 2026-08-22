"""Chiffres classiques : substitution et transposition."""

from __future__ import annotations

from db.models import (
    AffineInput,
    EnigmaInput,
    FrequencyAnalysisInput,
    HillInput,
    KeyTextInput,
    OneTimePadInput,
    ShiftInput,
    TextInput,
)
from registry.spec import Algorithm, Family, Maturity, Operation, TestVector
from utils import (
    affine_tool,
    caesar,
    columnar,
    enigma_tool,
    frequency_tool,
    hill_tool,
    otp_tool,
    playfair,
    rail_fence,
    substitution_tool,
    vigenere,
)

CAESAR = Algorithm(
    slug="caesar",
    name="Chiffre de Cesar",
    family=Family.CLASSICAL,
    summary=(
        "Decale chaque lettre d'un nombre fixe de positions. 25 cles possibles : "
        "on le casse a la main, en enumerant."
    ),
    maturity=Maturity.BROKEN,
    difficulty=1,
    year=-50,
    simulator="caesar",
    aliases=("rot", "decalage"),
    operations=(
        Operation(
            name="encrypt",
            input_model=ShiftInput,
            handler=lambda d: {"cipher": caesar.caesar_encrypt(d.text, d.shift)},
            summary="Chiffrer un texte par decalage",
        ),
        Operation(
            name="decrypt",
            input_model=ShiftInput,
            handler=lambda d: {"plain": caesar.caesar_decrypt(d.text, d.shift)},
            summary="Dechiffrer un texte decale",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "ATTACKATDAWN", "shift": 3},
            expected={"cipher": "DWWDFNDWGDZQ"},
            source="Suetone, Vie des douze Cesars (decalage de 3)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "DWWDFNDWGDZQ", "shift": 3},
            expected={"plain": "ATTACKATDAWN"},
            source="Suetone, Vie des douze Cesars (decalage de 3)",
        ),
        TestVector(
            operation="encrypt",
            inputs={"text": "HELLO, WORLD!", "shift": 13},
            expected={"cipher": "URYYB, JBEYQ!"},
            source="ROT13 (decalage de 13, involutif)",
        ),
    ),
)

VIGENERE = Algorithm(
    slug="vigenere",
    name="Chiffre de Vigenere",
    family=Family.CLASSICAL,
    summary=(
        "Un Cesar dont le decalage change a chaque lettre, dicte par une cle "
        "repetee. Reste inviole trois siecles, puis tombe par l'analyse de Kasiski."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    year=1553,
    simulator="vigenere",
    aliases=("chiffre indechiffrable",),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: {"cipher": vigenere.vigenere_encrypt(d.text, d.key)},
            summary="Chiffrer avec une cle repetee",
        ),
        Operation(
            name="decrypt",
            input_model=KeyTextInput,
            handler=lambda d: {"plain": vigenere.vigenere_decrypt(d.text, d.key)},
            summary="Dechiffrer avec la cle",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "ATTACKATDAWN", "key": "LEMON"},
            expected={"cipher": "LXFOPVEFRNHR"},
            source="Vecteur classique ATTACKATDAWN / LEMON",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "LXFOPVEFRNHR", "key": "LEMON"},
            expected={"plain": "ATTACKATDAWN"},
            source="Vecteur classique ATTACKATDAWN / LEMON",
        ),
    ),
)

PLAYFAIR = Algorithm(
    slug="playfair",
    name="Chiffre de Playfair",
    family=Family.CLASSICAL,
    summary=(
        "Chiffre les lettres par paires dans une grille 5x5. Premier chiffre "
        "digraphique pratique : l'analyse de frequence simple n'y suffit plus."
    ),
    maturity=Maturity.BROKEN,
    difficulty=3,
    year=1854,
    simulator="playfair",
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: {
                "cipher": playfair.playfair_encrypt(d.text, d.key),
                "digrams": playfair.build_digrams(d.text),
            },
            summary="Chiffrer par digrammes",
            description=(
                "Playfair ne conserve ni les espaces ni la longueur du message : "
                "la sortie est un flux de lettres."
            ),
        ),
        Operation(
            name="decrypt",
            input_model=KeyTextInput,
            handler=lambda d: {
                "plain": playfair.playfair_decrypt(d.text, d.key),
                # Le depadding est ambigu par nature : un X du message d'origine
                # peut etre retire. On expose donc aussi la sortie brute.
                "plain_raw": playfair.playfair_decrypt(d.text, d.key, remove_padding=False),
            },
            summary="Dechiffrer et retirer le bourrage",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "HIDETHEGOLDINTHETREESTUMP", "key": "PLAYFAIREXAMPLE"},
            expected={"cipher": "BMODZBXDNABEKUDMUIXMMOUVIF"},
            source="Wikipedia, exemple canonique PLAYFAIR EXAMPLE",
        ),
    ),
)

RAIL_FENCE = Algorithm(
    slug="railfence",
    name="Rail Fence",
    family=Family.CLASSICAL,
    summary=(
        "Ecrit le texte en zigzag sur plusieurs rails, puis lit rail par rail. "
        "Transposition pure : les lettres ne changent pas, seules leurs places."
    ),
    maturity=Maturity.BROKEN,
    difficulty=1,
    simulator="railfence",
    aliases=("zigzag", "cloture"),
    operations=(
        Operation(
            name="encrypt",
            input_model=ShiftInput,
            handler=lambda d: {
                "cipher": rail_fence.rail_fence_encrypt(d.text, d.shift),
                "grid": rail_fence.rail_fence_grid(d.text, d.shift),
            },
            summary="Chiffrer en zigzag (shift = nombre de rails)",
        ),
        Operation(
            name="decrypt",
            input_model=ShiftInput,
            handler=lambda d: {"plain": rail_fence.rail_fence_decrypt(d.text, d.shift)},
            summary="Dechiffrer un zigzag",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "WEAREDISCOVERED", "shift": 3},
            expected={"cipher": "WECRERDSOEEAIVD"},
            source="Vecteur canonique WEAREDISCOVERED / 3 rails",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "WECRERDSOEEAIVD", "shift": 3},
            expected={"plain": "WEAREDISCOVERED"},
            source="Vecteur canonique WEAREDISCOVERED / 3 rails",
        ),
        TestVector(
            operation="encrypt",
            # La ponctuation et les espaces sont conserves : c'est ce qui
            # distingue notre implementation de l'ancienne, qui les mangeait.
            inputs={"text": "HELLO, WORLD!", "shift": 4},
            expected={"cipher": "H !E,WDLOOLLR"},
            source="Aller-retour avec ponctuation (regression phase 1)",
        ),
    ),
)

COLUMNAR = Algorithm(
    slug="columnar",
    name="Transposition par colonnes",
    family=Family.CLASSICAL,
    summary=(
        "Ecrit le texte en grille, relit les colonnes dans l'ordre alphabetique "
        "de la cle. C'est l'algorithme que la route Rail Fence implementait "
        "reellement avant la v2."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    simulator="columnar",
    aliases=("transposition", "colonnes"),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: {
                "cipher": columnar.columnar_encrypt(d.text, d.key),
                "key_order": columnar.key_order(d.key),
            },
            summary="Chiffrer par transposition de colonnes",
        ),
        Operation(
            name="decrypt",
            input_model=KeyTextInput,
            handler=lambda d: {
                "plain": columnar.columnar_decrypt(d.text, d.key),
                "key_order": columnar.key_order(d.key),
            },
            summary="Dechiffrer une transposition",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "WEAREDISCOVEREDFLEEATONCE", "key": "ZEBRAS"},
            expected={"cipher": "EVLNACDTESEAROFODEECWIREE"},
            source="Vecteur canonique ZEBRAS (Wikipedia)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "EVLNACDTESEAROFODEECWIREE", "key": "ZEBRAS"},
            expected={"plain": "WEAREDISCOVEREDFLEEATONCE"},
            source="Vecteur canonique ZEBRAS (Wikipedia)",
        ),
    ),
)

ROT13 = Algorithm(
    slug="rot13",
    name="ROT13",
    family=Family.CLASSICAL,
    summary=(
        "Cesar fige a un decalage de 13 : sa propre inverse, puisque "
        "26 / 2 = 13. Pas un chiffre serieux — un obscurcissement de forum."
    ),
    maturity=Maturity.BROKEN,
    difficulty=1,
    simulator=None,
    aliases=("rot-13",),
    operations=(
        Operation(
            name="encrypt",
            input_model=TextInput,
            handler=lambda d: {"cipher": substitution_tool.rot13(d.text)},
            summary="Appliquer ROT13 (involutif : chiffrer = dechiffrer)",
        ),
        Operation(
            name="decrypt",
            input_model=TextInput,
            handler=lambda d: {"plain": substitution_tool.rot13(d.text)},
            summary="Appliquer ROT13 (involutif : chiffrer = dechiffrer)",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "Why did the chicken cross the road?"},
            expected={"cipher": "Jul qvq gur puvpxra pebff gur ebnq?"},
            source="Vecteur ROT13 classique (Usenet)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "Jul qvq gur puvpxra pebff gur ebnq?"},
            expected={"plain": "Why did the chicken cross the road?"},
            source="Vecteur ROT13 classique (Usenet), applique deux fois",
        ),
    ),
)

ATBASH = Algorithm(
    slug="atbash",
    name="Atbash",
    family=Family.CLASSICAL,
    summary=(
        "A<->Z, B<->Y, ... Le plus ancien chiffre de substitution connu, "
        "invente pour l'alphabet hebraique et applique ici a Z26."
    ),
    maturity=Maturity.BROKEN,
    difficulty=1,
    year=-500,
    simulator=None,
    operations=(
        Operation(
            name="encrypt",
            input_model=TextInput,
            handler=lambda d: {"cipher": substitution_tool.atbash(d.text)},
            summary="Appliquer Atbash (involutif : chiffrer = dechiffrer)",
        ),
        Operation(
            name="decrypt",
            input_model=TextInput,
            handler=lambda d: {"plain": substitution_tool.atbash(d.text)},
            summary="Appliquer Atbash (involutif : chiffrer = dechiffrer)",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "ATTACK AT DAWN"},
            expected={"cipher": "ZGGZXP ZG WZDM"},
            source="Miroir de l'alphabet latin (A<->Z, B<->Y, ...)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "ZGGZXP ZG WZDM"},
            expected={"plain": "ATTACK AT DAWN"},
            source="Miroir de l'alphabet latin, applique deux fois",
        ),
    ),
)

SUBSTITUTION = Algorithm(
    slug="substitution",
    name="Substitution simple",
    family=Family.CLASSICAL,
    summary=(
        "Remplace chaque lettre par une autre, fixee par une cle qui permute "
        "les 26 lettres. 26! cles possibles — et pourtant casse en minutes par "
        "l'analyse de frequence."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    simulator=None,
    aliases=("substitution monoalphabetique",),
    operations=(
        Operation(
            name="encrypt",
            input_model=KeyTextInput,
            handler=lambda d: {
                "cipher": substitution_tool.substitution_encrypt(d.text, d.key),
                "table": substitution_tool.substitution_table(d.key),
            },
            summary="Chiffrer avec une cle de 26 lettres (permutation de l'alphabet)",
        ),
        Operation(
            name="decrypt",
            input_model=KeyTextInput,
            handler=lambda d: {"plain": substitution_tool.substitution_decrypt(d.text, d.key)},
            summary="Dechiffrer avec la meme cle",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "HELLO", "key": "QWERTYUIOPASDFGHJKLZXCVBNM"},
            expected={"cipher": "ITSSG"},
            source="Cle QWERTY (disposition clavier comme permutation), calcule et verrouille",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "ITSSG", "key": "QWERTYUIOPASDFGHJKLZXCVBNM"},
            expected={"plain": "HELLO"},
            source="Cle QWERTY (disposition clavier comme permutation), calcule et verrouille",
        ),
    ),
)

AFFINE = Algorithm(
    slug="affine",
    name="Chiffre affine",
    family=Family.CLASSICAL,
    summary=(
        "Generalise Cesar : x -> a*x + b (mod 26). 'a' doit etre premier avec "
        "26 — sinon deux lettres claires distinctes se chiffreraient pareil."
    ),
    maturity=Maturity.BROKEN,
    difficulty=2,
    simulator=None,
    operations=(
        Operation(
            name="encrypt",
            input_model=AffineInput,
            handler=lambda d: {"cipher": affine_tool.affine_encrypt(d.text, d.a, d.b)},
            summary="Chiffrer par x -> a*x + b (mod 26)",
        ),
        Operation(
            name="decrypt",
            input_model=AffineInput,
            handler=lambda d: {"plain": affine_tool.affine_decrypt(d.text, d.a, d.b)},
            summary="Dechiffrer par l'inverse modulaire de a",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "AFFINE CIPHER", "a": 5, "b": 8},
            expected={"cipher": "IHHWVC SWFRCP"},
            source="Calcule et verrouille (a=5, b=8, a^-1=21 mod 26)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "IHHWVC SWFRCP", "a": 5, "b": 8},
            expected={"plain": "AFFINE CIPHER"},
            source="Calcule et verrouille (a=5, b=8, a^-1=21 mod 26)",
        ),
    ),
)

HILL = Algorithm(
    slug="hill",
    name="Chiffre de Hill (2x2)",
    family=Family.CLASSICAL,
    summary=(
        "Chaque paire de lettres devient un vecteur, multiplie par une matrice "
        "de cle mod 26. Premier chiffre a melanger plusieurs lettres par de "
        "l'algebre lineaire plutot que lettre par lettre."
    ),
    maturity=Maturity.BROKEN,
    difficulty=3,
    year=1929,
    simulator=None,
    operations=(
        Operation(
            name="encrypt",
            input_model=HillInput,
            handler=lambda d: {"cipher": hill_tool.hill_encrypt(d.text, d.a, d.b, d.c, d.d)},
            summary="Chiffrer par blocs de 2 lettres (bourrage X si longueur impaire)",
        ),
        Operation(
            name="decrypt",
            input_model=HillInput,
            handler=lambda d: {"plain": hill_tool.hill_decrypt(d.text, d.a, d.b, d.c, d.d)},
            summary="Dechiffrer par la matrice inverse mod 26",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "HELP", "a": 3, "b": 3, "c": 2, "d": 5},
            expected={"cipher": "HIAT"},
            source="Exemple textbook canonique (matrice [[3,3],[2,5]], determinant 9)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "HIAT", "a": 3, "b": 3, "c": 2, "d": 5},
            expected={"plain": "HELP"},
            source="Exemple textbook canonique (matrice [[3,3],[2,5]], determinant 9)",
        ),
    ),
)

ONE_TIME_PAD = Algorithm(
    slug="otp",
    name="One-Time Pad",
    family=Family.CLASSICAL,
    summary=(
        "Le seul chiffre au secret parfait, prouve par Shannon en 1949 — a "
        "condition d'une cle aussi longue que le message, aleatoire, et jamais "
        "reutilisee. C'est justement pourquoi il est inutilisable en pratique."
    ),
    maturity=Maturity.CURRENT,
    difficulty=2,
    year=1917,
    simulator=None,
    aliases=("masque jetable", "vernam"),
    operations=(
        Operation(
            name="encrypt",
            input_model=OneTimePadInput,
            handler=lambda d: {"cipher": otp_tool.otp_encrypt(d.text, d.key)},
            summary="Chiffrer (la cle doit couvrir chaque lettre du texte)",
        ),
        Operation(
            name="decrypt",
            input_model=OneTimePadInput,
            handler=lambda d: {"plain": otp_tool.otp_decrypt(d.text, d.key)},
            summary="Dechiffrer avec la meme cle",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={"text": "HELLO", "key": "XMCKL"},
            expected={"cipher": "EQNVZ"},
            source="Calcule et verrouille (cle aleatoire de meme longueur que le message)",
        ),
        TestVector(
            operation="decrypt",
            inputs={"text": "EQNVZ", "key": "XMCKL"},
            expected={"plain": "HELLO"},
            source="Calcule et verrouille (cle aleatoire de meme longueur que le message)",
        ),
    ),
)

FREQUENCY_ANALYSIS = Algorithm(
    slug="frequencyanalysis",
    name="Analyse de frequence",
    family=Family.CLASSICAL,
    summary=(
        "Pas un chiffre : l'outil qui les casse. Compte les lettres d'un texte "
        "et calcule son indice de coincidence (Friedman, 1922) — la signature "
        "qui distingue un clair (ou un Cesar) d'un Vigenere bien melange."
    ),
    maturity=Maturity.EDUCATIONAL,
    difficulty=2,
    year=1922,
    simulator=None,
    aliases=("indice de coincidence", "cryptanalyse"),
    operations=(
        Operation(
            name="analyze",
            input_model=FrequencyAnalysisInput,
            handler=lambda d: frequency_tool.analyze(d.text),
            summary="Compter les lettres et calculer l'indice de coincidence",
            length_field="text",
        ),
    ),
    vectors=(
        TestVector(
            operation="analyze",
            inputs={"text": "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"},
            expected={"letter_count": 35, "index_of_coincidence": 0.0218},
            source="Calcule et verrouille (pangramme anglais, distribution quasi uniforme)",
        ),
    ),
)

ENIGMA = Algorithm(
    slug="enigma",
    name="Enigma",
    family=Family.CLASSICAL,
    summary=(
        "La machine a rotors allemande de la Seconde Guerre mondiale. Trois "
        "rotors interchangeables, un reflecteur, un tableau de connexions — "
        "et une faiblesse structurelle (aucune lettre ne se chiffre en "
        "elle-meme) qui a permis a Bletchley Park de la casser."
    ),
    maturity=Maturity.BROKEN,
    difficulty=4,
    year=1918,
    simulator=None,
    aliases=("machine a rotors", "bletchley park"),
    operations=(
        Operation(
            name="encrypt",
            input_model=EnigmaInput,
            handler=lambda d: enigma_tool.enigma_encrypt(
                d.text, d.rotors.split(), d.positions, d.ring_settings, d.plugboard
            ),
            summary="Chiffrer (rotors, positions, reglages d'anneau, tableau de connexions)",
        ),
        Operation(
            name="decrypt",
            input_model=EnigmaInput,
            handler=lambda d: enigma_tool.enigma_decrypt(
                d.text, d.rotors.split(), d.positions, d.ring_settings, d.plugboard
            ),
            summary="Dechiffrer (memes reglages : Enigma est sa propre inverse)",
        ),
    ),
    vectors=(
        TestVector(
            operation="encrypt",
            inputs={
                "text": "AAAAA",
                "rotors": "I II III",
                "positions": "AAA",
                "ring_settings": "AAA",
                "plugboard": "",
            },
            expected={"result": "BDZGO"},
            source="Vecteur de reference Enigma I / reflecteur B, rotors I-II-III position AAA",
        ),
    ),
)

ALGORITHMS = (
    CAESAR,
    VIGENERE,
    PLAYFAIR,
    RAIL_FENCE,
    COLUMNAR,
    ROT13,
    ATBASH,
    SUBSTITUTION,
    AFFINE,
    HILL,
    ONE_TIME_PAD,
    FREQUENCY_ANALYSIS,
    ENIGMA,
)
