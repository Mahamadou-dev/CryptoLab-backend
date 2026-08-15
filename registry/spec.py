"""
Vocabulaire du registre d'algorithmes.

Avant la v2, ajouter un algorithme demandait de toucher cinq fichiers : le
module de calcul, un modele Pydantic, une paire de routes ecrites a la main, la
table du simulateur, et le client TypeScript. Les routes etaient copiees-collees
les unes des autres, et rien ne garantissait qu'un algorithme soit teste contre
un vecteur officiel.

Un algorithme est desormais un objet qui declare ce qu'il est, ce qu'il sait
faire, et comment le prouver. Les routes, la documentation OpenAPI, le catalogue
public et les tests de vecteurs en sont tous derives.

**Ajouter un algorithme = ecrire un fichier et l'enregistrer.**
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel


class Family(str, Enum):
    """Famille d'un algorithme. Determine le prefixe d'URL et le classement."""

    CLASSICAL = "classical"
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"

    @property
    def prefix(self) -> str:
        # `symmetric` est expose sous /api/modern : c'est l'URL publique
        # historique, et la casser ferait tomber les pages en ligne.
        return {
            Family.CLASSICAL: "/api/classical",
            Family.SYMMETRIC: "/api/modern",
            Family.ASYMMETRIC: "/api/asymmetric",
            Family.HASH: "/api/hash",
        }[self]

    @property
    def label(self) -> str:
        return {
            Family.CLASSICAL: "Chiffres classiques",
            Family.SYMMETRIC: "Symetrique moderne",
            Family.ASYMMETRIC: "Clef publique",
            Family.HASH: "Hachage et derivation",
        }[self]


class Maturity(str, Enum):
    """
    Ce qu'on a le droit de faire avec cet algorithme.

    CryptoLab enseigne autant par les algorithmes casses que par les sûrs : la
    distinction doit etre portee par la donnee, pas par un paragraphe d'article
    que personne ne lit.
    """

    #: Utilisable aujourd'hui pour proteger de vraies donnees.
    CURRENT = "current"
    #: Historiquement important, aujourd'hui casse ou trivialement cassable.
    BROKEN = "broken"
    #: Correct sur le principe, mais l'implementation ici est pedagogique.
    EDUCATIONAL = "educational"


@dataclass(frozen=True)
class TestVector:
    """
    Un vecteur de test officiel.

    C'est le contrat de l'algorithme. La CI les rejoue tous a chaque commit, et
    le catalogue public annonce leur nombre : la preuve devient un argument
    pedagogique, pas une note interne.
    """

    #: Nom de l'operation a executer (`encrypt`, `hash`, ...).
    operation: str
    #: Arguments passes au modele d'entree de l'operation.
    inputs: dict[str, Any]
    #: Sous-ensemble attendu de la reponse. Les champs absents ne sont pas verifies.
    expected: dict[str, Any]
    #: D'ou vient ce vecteur : « FIPS 197 annexe B », « RFC 3602 §4 », ...
    source: str


@dataclass(frozen=True)
class Operation:
    """Une operation exposee par un algorithme."""

    #: `encrypt`, `decrypt`, `hash`, `verify`, `generate-keys`, ...
    name: str
    #: Modele Pydantic validant le corps de la requete.
    input_model: type[BaseModel] | None
    #: Recoit l'entree validee, renvoie le contenu de `data`.
    handler: Callable[..., dict]
    summary: str
    description: str = ""
    method: str = "POST"
    #: Chemin relatif au prefixe de famille. Par defaut `/<slug>/<name>`.
    path: str | None = None
    #: Champ dont la longueur alimente les statistiques anonymes.
    length_field: str = "text"

    def resolved_path(self, slug: str) -> str:
        return self.path if self.path is not None else f"/{slug}/{self.name}"


@dataclass(frozen=True)
class Algorithm:
    """Un algorithme et tout ce qui le rend exploitable."""

    #: Identifiant stable, en minuscules. Apparait dans les URL.
    slug: str
    #: Nom affiche.
    name: str
    family: Family
    #: Une phrase : ce que l'algorithme fait, et pourquoi il compte.
    summary: str
    operations: tuple[Operation, ...]
    maturity: Maturity = Maturity.EDUCATIONAL
    #: 1 = accessible en premiere annee, 5 = niveau master.
    difficulty: int = 1
    #: Annee de publication ou de premiere utilisation attestee.
    year: int | None = None
    vectors: tuple[TestVector, ...] = ()
    #: Nom du simulateur pas a pas, s'il en existe un (`/api/simulate/<slug>`).
    simulator: str | None = None
    #: Termes de recherche supplementaires.
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def operation(self, name: str) -> Operation | None:
        return next((op for op in self.operations if op.name == name), None)

    def describe(self) -> dict[str, Any]:
        """Fiche publique, servie par `/api/algorithms`."""
        return {
            "slug": self.slug,
            "name": self.name,
            "family": self.family.value,
            "family_label": self.family.label,
            "summary": self.summary,
            "maturity": self.maturity.value,
            "difficulty": self.difficulty,
            "year": self.year,
            "simulator": self.simulator,
            "aliases": list(self.aliases),
            "vector_count": len(self.vectors),
            "vector_sources": sorted({vector.source for vector in self.vectors}),
            "operations": [
                {
                    "name": op.name,
                    "method": op.method,
                    "path": f"{self.family.prefix}{op.resolved_path(self.slug)}",
                    "summary": op.summary,
                    "schema": op.input_model.model_json_schema() if op.input_model else None,
                }
                for op in self.operations
            ],
        }


class Registry:
    """Collection d'algorithmes, indexee par slug."""

    def __init__(self) -> None:
        self._algorithms: dict[str, Algorithm] = {}

    def register(self, algorithm: Algorithm) -> Algorithm:
        if algorithm.slug in self._algorithms:
            raise ValueError(f"Algorithme deja enregistre : {algorithm.slug}")
        self._algorithms[algorithm.slug] = algorithm
        return algorithm

    def get(self, slug: str) -> Algorithm | None:
        return self._algorithms.get(slug)

    def all(self) -> list[Algorithm]:
        return sorted(self._algorithms.values(), key=lambda a: (a.family.value, a.slug))

    def vectors(self) -> list[tuple[Algorithm, TestVector]]:
        """Tous les vecteurs du registre, a plat. Consomme par les tests."""
        return [(algo, vector) for algo in self.all() for vector in algo.vectors]

    def __len__(self) -> int:
        return len(self._algorithms)

    def __contains__(self, slug: object) -> bool:
        return slug in self._algorithms
