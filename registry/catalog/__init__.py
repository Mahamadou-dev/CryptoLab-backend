"""
Catalogue des algorithmes exposes par CryptoLab.

Ajouter un algorithme : l'ecrire dans le fichier de sa famille, l'ajouter au
tuple `ALGORITHMS` de ce fichier, et c'est tout. Les routes, la documentation
OpenAPI, l'endpoint `/api/algorithms` et les tests de vecteurs suivent.
"""

from __future__ import annotations

from registry.spec import Registry

from . import asymmetric, classical, hashing, symmetric

registry = Registry()

for module in (classical, symmetric, asymmetric, hashing):
    for algorithm in module.ALGORITHMS:
        registry.register(algorithm)

__all__ = ["registry"]
