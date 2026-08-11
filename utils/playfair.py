"""
Chiffre de Playfair.

Corrections apportees a l'ancienne version :

1. Les digrammes sont formes sur le message ENTIER, plus mot par mot. L'ancien
   decoupage produisait des paires absurdes : "A B" donnait "GA AZ", chaque mot
   d'une lettre etant bourre de son propre "X".
2. Le dechiffrement retire le bourrage. "HELLO WORLD" revenait en
   "HELXLO WORLDX" ; il revient maintenant en "HELLOWORLD".

Playfair ne conserve NI les espaces NI la longueur : il travaille sur des
paires de lettres et insere du bourrage. C'est une propriete de l'algorithme,
pas une limite de l'implementation — la sortie est donc un flux de lettres.
"""

import string

PADDING = "X"
# Lettre de remplacement quand un doublon est deja un X (ex: "XX").
ALT_PADDING = "Q"


def generate_playfair_matrix(key: str) -> list[list[str]]:
    """
    Genere la matrice Playfair 5x5. I et J partagent la meme case.
    """
    source = key.upper().replace("J", "I") + string.ascii_uppercase.replace("J", "")
    letters: list[str] = []
    seen = set()
    for char in source:
        if char.isalpha() and char not in seen:
            letters.append(char)
            seen.add(char)
    return [letters[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix: list[list[str]], char: str) -> tuple[int, int]:
    """Position (ligne, colonne) d'une lettre dans la matrice, ou (-1, -1)."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return -1, -1


def normalise(text: str) -> str:
    """Ne garde que les lettres, en majuscules, J fondu dans I."""
    return "".join(c for c in text.upper().replace("J", "I") if c.isalpha())


def build_digrams(text: str) -> list[str]:
    """
    Decoupe le message entier en digrammes, en appliquant les deux regles
    classiques :

    - une paire de lettres identiques est separee par un X (ou un Q si la
      lettre doublee est deja un X) ;
    - un message de longueur impaire est complete par un X final.
    """
    letters = normalise(text)
    digrams: list[str] = []

    i = 0
    while i < len(letters):
        first = letters[i]

        if i + 1 >= len(letters):
            # Derniere lettre orpheline : on complete.
            filler = ALT_PADDING if first == PADDING else PADDING
            digrams.append(first + filler)
            break

        second = letters[i + 1]
        if first == second:
            filler = ALT_PADDING if first == PADDING else PADDING
            digrams.append(first + filler)
            i += 1  # la seconde lettre repart dans le digramme suivant
        else:
            digrams.append(first + second)
            i += 2

    return digrams


def strip_padding(text: str) -> str:
    """
    Retire le bourrage insere au chiffrement.

    Heuristique standard : un X (ou Q) encadre par deux lettres identiques a
    ete insere pour separer un doublon, et un X final complete une longueur
    impaire. La regle est ambigue par nature — un vrai X du message peut etre
    retire — d'ou l'affichage du texte brut a cote du texte nettoye dans la
    trace pedagogique.
    """
    chars = list(text)

    # 1. Bourrage intercalaire : A X A -> A A
    cleaned: list[str] = []
    i = 0
    while i < len(chars):
        if (
            0 < i < len(chars) - 1
            and chars[i] in (PADDING, ALT_PADDING)
            and chars[i - 1] == chars[i + 1]
        ):
            i += 1  # on saute le caractere de bourrage
            continue
        cleaned.append(chars[i])
        i += 1

    # 2. Bourrage final
    if len(cleaned) >= 2 and cleaned[-1] in (PADDING, ALT_PADDING):
        cleaned.pop()

    return "".join(cleaned)


def _transform_digram(matrix: list[list[str]], pair: str, direction: int) -> str:
    """
    Applique la regle Playfair a un digramme.

    direction = +1 pour chiffrer (on descend / on va a droite),
    direction = -1 pour dechiffrer.
    """
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    if r1 < 0 or r2 < 0:
        return pair

    if r1 == r2:  # meme ligne : on se decale horizontalement
        return matrix[r1][(c1 + direction) % 5] + matrix[r2][(c2 + direction) % 5]
    if c1 == c2:  # meme colonne : on se decale verticalement
        return matrix[(r1 + direction) % 5][c1] + matrix[(r2 + direction) % 5][c2]
    # rectangle : on echange les colonnes (identique dans les deux sens)
    return matrix[r1][c2] + matrix[r2][c1]


def playfair_encrypt(plain_text: str, key: str) -> str:
    """Chiffre un texte avec Playfair. La sortie est un flux de lettres."""
    matrix = generate_playfair_matrix(key)
    return "".join(
        _transform_digram(matrix, pair, +1) for pair in build_digrams(plain_text)
    )


def playfair_decrypt(cipher_text: str, key: str, remove_padding: bool = True) -> str:
    """
    Dechiffre un texte Playfair.

    Args:
        remove_padding: retire le bourrage X/Q insere au chiffrement.
            Passer False pour obtenir la sortie brute, digramme par digramme.
    """
    matrix = generate_playfair_matrix(key)
    letters = normalise(cipher_text)

    raw = "".join(
        _transform_digram(matrix, letters[i:i + 2], -1)
        for i in range(0, len(letters) - 1, 2)
    )

    # Une lettre orpheline (chiffre tronque) est rendue telle quelle.
    if len(letters) % 2:
        raw += letters[-1]

    return strip_padding(raw) if remove_padding else raw
