"""Chiffres classiques : substitution et transposition."""

from __future__ import annotations

from db.models import KeyTextInput, ShiftInput
from registry.spec import Algorithm, Family, Maturity, Operation, TestVector
from utils import caesar, columnar, playfair, rail_fence, vigenere

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

ALGORITHMS = (CAESAR, VIGENERE, PLAYFAIR, RAIL_FENCE, COLUMNAR)
