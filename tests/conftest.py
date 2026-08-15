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


def unwrap(response) -> dict:
    """
    Verifie l'enveloppe `{ok, data, error}` et retourne `data`.

    Toute reponse de l'API passe par cette forme depuis la phase 2 : le helper
    verifie donc le contrat en meme temps qu'il extrait le contenu.
    """
    body = response.json()
    assert set(body) == {"ok", "data", "error"}, body
    assert body["ok"] is True, body
    assert body["error"] is None, body
    return body["data"]


def error_of(response) -> dict:
    """Verifie une enveloppe en echec et retourne l'erreur."""
    body = response.json()
    assert set(body) == {"ok", "data", "error"}, body
    assert body["ok"] is False, body
    assert body["data"] is None, body
    return body["error"]
