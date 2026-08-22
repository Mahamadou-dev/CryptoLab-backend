"""
Analyse de frequence et indice de coincidence.

Ce ne sont pas des chiffres : ce sont les outils qui les cassent. La
distribution des lettres d'un texte en clair epouse celle de la langue ;
Cesar et la substitution simple ne peuvent pas l'effacer, seulement la
permuter — d'ou l'analyse de frequence. L'indice de coincidence (Friedman,
1922) mesure a quel point cette distribution reste inegale : proche de 0.067
pour un texte francais/anglais en clair ou un Cesar, proche de 1/26 = 0.0385
pour un texte polyalphabetique bien melange (Vigenere a longue cle) ou
aleatoire.
"""

from __future__ import annotations

import string
from collections import Counter

ALPHABET = string.ascii_uppercase

#: Reference usuelle pour un texte anglais/francais en clair.
NATURAL_LANGUAGE_IC = 0.067
#: Reference pour une distribution uniforme (alphabet melange au hasard).
UNIFORM_IC = 1 / 26


def letter_frequencies(text: str) -> dict[str, int]:
    """Compte brut de chaque lettre A-Z (casse ignoree, non-lettres exclues)."""
    letters = [char for char in text.upper() if char.isalpha()]
    counts = Counter(letters)
    return {letter: counts.get(letter, 0) for letter in ALPHABET}


def index_of_coincidence(text: str) -> float:
    """
    IC = sum(f_i * (f_i - 1)) / (N * (N - 1))

    Probabilite que deux lettres tirees au hasard dans le texte soient
    identiques. Ne depend d'aucune cle : c'est une propriete du texte lui-meme.
    """
    letters = [char for char in text.upper() if char.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    numerator = sum(count * (count - 1) for count in counts.values())
    return numerator / (n * (n - 1))


def analyze(text: str) -> dict:
    letters = [char for char in text.upper() if char.isalpha()]
    frequencies = letter_frequencies(text)
    total = len(letters)
    ic = index_of_coincidence(text)
    return {
        "letter_count": total,
        "frequencies": frequencies,
        "percentages": {
            letter: round(100 * count / total, 2) if total else 0.0
            for letter, count in frequencies.items()
        },
        "index_of_coincidence": round(ic, 4),
        "closer_to": (
            "natural_language"
            if abs(ic - NATURAL_LANGUAGE_IC) < abs(ic - UNIFORM_IC)
            else "uniform_or_polyalphabetic"
        ),
    }
