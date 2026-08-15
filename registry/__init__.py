"""
Registre d'algorithmes de CryptoLab.

Point d'entree unique : `from registry import registry`.
"""

from __future__ import annotations

from .catalog import registry
from .errors import (
    CryptoLabError,
    DecryptionFailed,
    InvalidInput,
    InvalidKey,
    UnknownAlgorithm,
    UnsupportedOperation,
)
from .routes import build_catalog_router, build_routers
from .spec import Algorithm, Family, Maturity, Operation, Registry, TestVector

__all__ = [
    "Algorithm",
    "CryptoLabError",
    "DecryptionFailed",
    "Family",
    "InvalidInput",
    "InvalidKey",
    "Maturity",
    "Operation",
    "Registry",
    "TestVector",
    "UnknownAlgorithm",
    "UnsupportedOperation",
    "build_catalog_router",
    "build_routers",
    "registry",
]
