"""
Connexion optionnelle a MongoDB.

CryptoLab fonctionne entierement sans base de donnees. La persistance est
desactivee par defaut et ne sert QUE a compter des statistiques d'usage
anonymes (voir db/crud.py). Aucun texte clair, aucune cle et aucun resultat
de chiffrement n'est jamais ecrit sur disque.

Pour l'activer : CRYPTOLAB_ENABLE_STATS=true + MONGO_URI dans l'environnement.
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

STATS_ENABLED = os.getenv("CRYPTOLAB_ENABLE_STATS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "cryptolab")

_db = None
_initialised = False


def _init() -> None:
    """Tente la connexion une seule fois, a la premiere utilisation."""
    global _db, _initialised
    _initialised = True

    if not STATS_ENABLED:
        logger.info("Statistiques desactivees (CRYPTOLAB_ENABLE_STATS=false).")
        return

    if not MONGO_URI:
        logger.warning(
            "CRYPTOLAB_ENABLE_STATS=true mais MONGO_URI est absent : "
            "statistiques desactivees."
        )
        return

    try:
        from pymongo import MongoClient

        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        _db = client[DB_NAME]
        logger.info("Connecte a MongoDB (base : %s).", DB_NAME)
    except Exception as exc:  # pragma: no cover - depend de l'environnement
        logger.warning("Connexion MongoDB impossible, statistiques desactivees : %s", exc)
        _db = None


def get_db() -> object | None:
    """
    Retourne la base si les statistiques sont actives et joignables, sinon None.

    Ne leve jamais : l'application doit fonctionner sans base.
    """
    if not _initialised:
        _init()
    return _db


def stats_enabled() -> bool:
    """True si les statistiques anonymes sont reellement operationnelles."""
    return get_db() is not None
