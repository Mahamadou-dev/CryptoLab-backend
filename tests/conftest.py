"""Configuration partagee de la suite de tests."""

import os
import sys
from pathlib import Path

# Les statistiques doivent rester coupees pendant les tests : aucun test ne
# doit pouvoir ecrire dans une base.
os.environ.setdefault("CRYPTOLAB_ENABLE_STATS", "false")

# Permet `from utils import ...` sans installer le paquet.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    """Client HTTP de test, partage par toute la session."""
    return TestClient(app)
