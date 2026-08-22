"""
Machine Enigma (modele I historique) : trois rotors interchangeables parmi
cinq, un reflecteur fixe (B), un tableau de connexions optionnel.

Purement pedagogique et volontairement fidele au mecanisme reel — y compris
son anomalie de double-pas — plutot qu'une version simplifiee : c'est cette
fidelite qui rend visible pourquoi Bletchley Park a pu l'attaquer (le
reflecteur garantit qu'une lettre ne se chiffre jamais en elle-meme, une
faiblesse structurelle exploitee par la bombe de Turing).
"""

from __future__ import annotations

from registry.errors import InvalidInput

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#: Cablage historique des cinq rotors de l'Enigma I, et la lettre a laquelle
#: chacun fait avancer son voisin de gauche (l'encoche).
ROTOR_WIRINGS: dict[str, tuple[str, str]] = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}

#: Reflecteur B : la version la plus repandue sur l'Enigma I de la Wehrmacht.
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"


class _Rotor:
    def __init__(self, name: str, ring: int, position: int) -> None:
        self.name = name
        self.wiring, self.notch = ROTOR_WIRINGS[name]
        self.ring = ring
        self.position = position

    def at_notch(self) -> bool:
        return ALPHABET[self.position] == self.notch

    def step(self) -> None:
        self.position = (self.position + 1) % 26

    def forward(self, letter: str) -> str:
        offset = (ALPHABET.index(letter) + self.position - self.ring) % 26
        out = self.wiring[offset]
        return ALPHABET[(ALPHABET.index(out) - self.position + self.ring) % 26]

    def backward(self, letter: str) -> str:
        offset = (ALPHABET.index(letter) + self.position - self.ring) % 26
        out_letter = ALPHABET[offset]
        j = self.wiring.index(out_letter)
        return ALPHABET[(j - self.position + self.ring) % 26]


def _parse_plugboard(spec: str) -> dict[str, str]:
    pairs = spec.upper().split()
    table: dict[str, str] = {}
    seen: set[str] = set()
    for pair in pairs:
        if len(pair) != 2 or not pair.isalpha():
            raise InvalidInput(
                f"'{pair}' n'est pas une paire de lettres valide pour le tableau de connexions."
            )
        a, b = pair[0], pair[1]
        if a in seen or b in seen:
            raise InvalidInput(f"La lettre apparait dans plus d'une paire du tableau : '{pair}'.")
        table[a] = b
        table[b] = a
        seen.add(a)
        seen.add(b)
    return table


def _build_rotors(rotor_names: list[str], positions: str, ring_settings: str) -> list[_Rotor]:
    if len(set(rotor_names)) != 3:
        raise InvalidInput("Les trois rotors doivent etre distincts.")
    for name in rotor_names:
        if name not in ROTOR_WIRINGS:
            raise InvalidInput(f"Rotor inconnu : '{name}'. Choix possibles : I, II, III, IV, V.")
    if not (positions.isalpha() and len(positions) == 3):
        raise InvalidInput("Les positions de depart sont trois lettres, ex. 'AAA'.")
    if not (ring_settings.isalpha() and len(ring_settings) == 3):
        raise InvalidInput("Les reglages d'anneau sont trois lettres, ex. 'AAA'.")

    return [
        _Rotor(name, ring=ALPHABET.index(ring.upper()), position=ALPHABET.index(pos.upper()))
        for name, ring, pos in zip(rotor_names, ring_settings, positions, strict=True)
    ]


def _step(rotors: list[_Rotor]) -> None:
    """
    Avance les rotors d'une position, en reproduisant l'anomalie de
    double-pas : quand le rotor du milieu est sur son encoche, lui ET le
    rotor de gauche avancent au meme coup — pas seulement le rotor de gauche.
    C'est une bizarrerie mecanique du vrai Enigma, pas un choix de conception.
    """
    left, middle, right = rotors
    middle_will_step = middle.at_notch()
    left_will_step = middle.at_notch()
    if right.at_notch():
        middle_will_step = True
    right.step()
    if middle_will_step:
        middle.step()
    if left_will_step:
        left.step()


def _encrypt_letter(letter: str, rotors: list[_Rotor], plugboard: dict[str, str]) -> str:
    letter = plugboard.get(letter, letter)
    _step(rotors)
    left, middle, right = rotors
    for rotor in (right, middle, left):
        letter = rotor.forward(letter)
    letter = REFLECTOR_B[ALPHABET.index(letter)]
    for rotor in (left, middle, right):
        letter = rotor.backward(letter)
    return plugboard.get(letter, letter)


def enigma_encrypt(
    text: str,
    rotors: list[str],
    positions: str,
    ring_settings: str = "AAA",
    plugboard: str = "",
) -> dict:
    """
    Chiffre (ou dechiffre, la machine est sa propre inverse) `text`.

    Les caracteres non alphabetiques traversent sans etre chiffres ni faire
    avancer les rotors — l'Enigma historique ne traitait que des lettres.
    """
    machine = _build_rotors(rotors, positions, ring_settings)
    plug_table = _parse_plugboard(plugboard)

    output = []
    steps = []
    for char in text:
        if char.isalpha():
            positions_before = "".join(ALPHABET[r.position] for r in machine)
            result = _encrypt_letter(char.upper(), machine, plug_table)
            positions_after = "".join(ALPHABET[r.position] for r in machine)
            output.append(result)
            steps.append(
                {
                    "input": char.upper(),
                    "output": result,
                    "rotor_positions_before": positions_before,
                    "rotor_positions_after": positions_after,
                }
            )
        else:
            output.append(char)

    return {"result": "".join(output), "steps": steps}


#: L'Enigma est sa propre inverse a reglages identiques : dechiffrer, c'est
#: rechiffrer depuis la meme position de depart.
enigma_decrypt = enigma_encrypt
