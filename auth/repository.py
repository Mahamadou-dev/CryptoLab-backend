"""
Stockage des comptes utilisateurs.

Deux implementations derriere la meme interface :

* `MongoUserRepository` — la base `cryptolab_auth` du cluster Atlas. Utilisee
  des que `MONGO_URI` est renseigne.
* `MemoryUserRepository` — un dictionnaire en memoire, pour le developpement
  local et la suite de tests. Aucune dependance, aucun reseau.

L'interface est volontairement minuscule : trouver par e-mail, trouver par id,
creer. Tout le reste (validation, hachage, jetons) vit ailleurs.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Protocol

logger = logging.getLogger(__name__)

AUTH_DB_NAME = os.getenv("CRYPTOLAB_AUTH_DB", "cryptolab_auth")
USERS_COLLECTION = "users"


class DuplicateEmailError(Exception):
    """Un compte existe deja pour cet e-mail."""


class RepositoryUnavailableError(Exception):
    """Le stockage des comptes est injoignable."""


def normalise_email(email: str) -> str:
    """
    Forme canonique d'un e-mail : minuscules, sans espaces.

    Sans cela `Alice@X.com` et `alice@x.com` creeraient deux comptes distincts,
    et l'index unique ne servirait a rien.
    """
    return email.strip().lower()


class UserRepository(Protocol):
    """Interface de stockage des comptes."""

    def find_by_email(self, email: str) -> dict | None: ...

    def find_by_id(self, user_id: str) -> dict | None: ...

    def create(self, document: dict) -> dict: ...


def new_user_document(
    *,
    email: str,
    password_hash: str,
    first_name: str,
    last_name: str,
    country: str,
    city: str,
) -> dict:
    """Construit un document utilisateur complet, pret a etre insere."""
    return {
        "_id": uuid.uuid4().hex,
        "email": normalise_email(email),
        "password_hash": password_hash,
        "first_name": first_name,
        "last_name": last_name,
        "country": country,
        "city": city,
        "created_at": datetime.now(timezone.utc),
    }


# --- Implementation memoire ---------------------------------------------------

class MemoryUserRepository:
    """Stockage en memoire du processus. Perdu au redemarrage, et c'est voulu."""

    def __init__(self) -> None:
        self._by_id: dict[str, dict] = {}
        self._id_by_email: dict[str, str] = {}

    def find_by_email(self, email: str) -> dict | None:
        user_id = self._id_by_email.get(normalise_email(email))
        return dict(self._by_id[user_id]) if user_id else None

    def find_by_id(self, user_id: str) -> dict | None:
        found = self._by_id.get(user_id)
        return dict(found) if found else None

    def create(self, document: dict) -> dict:
        email = document["email"]
        if email in self._id_by_email:
            raise DuplicateEmailError(email)
        self._by_id[document["_id"]] = dict(document)
        self._id_by_email[email] = document["_id"]
        return dict(document)

    def clear(self) -> None:
        """Remet le depot a zero. Reserve aux tests."""
        self._by_id.clear()
        self._id_by_email.clear()


# --- Implementation MongoDB ---------------------------------------------------

class MongoUserRepository:
    """Comptes stockes dans la base `cryptolab_auth` du cluster Atlas."""

    def __init__(self, uri: str, db_name: str = AUTH_DB_NAME) -> None:
        from pymongo import ASCENDING, MongoClient
        from pymongo.errors import DuplicateKeyError

        self._duplicate_key_error = DuplicateKeyError
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        self._users = client[db_name][USERS_COLLECTION]

        # Index unique : la vraie garantie d'unicite. La verification applicative
        # faite avant l'insertion ne suffit pas — deux inscriptions simultanees
        # sur le meme e-mail la franchiraient toutes les deux.
        self._users.create_index([("email", ASCENDING)], unique=True, name="email_unique")
        logger.info("Comptes stockes dans MongoDB (base : %s).", db_name)

    def find_by_email(self, email: str) -> dict | None:
        return self._users.find_one({"email": normalise_email(email)})

    def find_by_id(self, user_id: str) -> dict | None:
        return self._users.find_one({"_id": user_id})

    def create(self, document: dict) -> dict:
        try:
            self._users.insert_one(document)
        except self._duplicate_key_error as exc:
            raise DuplicateEmailError(document["email"]) from exc
        return document


# --- Selection ----------------------------------------------------------------

_repository: UserRepository | None = None
_resolved = False


def get_repository() -> UserRepository:
    """
    Retourne le depot de comptes, instancie une seule fois.

    Raises:
        RepositoryUnavailableError: en production, si Mongo est absent ou
            injoignable. Mieux vaut une 503 explicite que des comptes crees en
            memoire et perdus au prochain redemarrage.
    """
    global _repository, _resolved

    if _resolved and _repository is not None:
        return _repository

    _resolved = True
    uri = os.getenv("MONGO_URI", "").strip()
    in_production = os.getenv("CRYPTOLAB_ENV", "development").strip().lower() == "production"

    if not uri:
        if in_production:
            _resolved = False
            raise RepositoryUnavailableError(
                "MONGO_URI est absent : impossible de gerer des comptes en production."
            )
        logger.warning(
            "MONGO_URI absent : comptes stockes en memoire. "
            "Ils disparaitront a l'arret du serveur."
        )
        _repository = MemoryUserRepository()
        return _repository

    try:
        _repository = MongoUserRepository(uri)
    except Exception as exc:
        _resolved = False
        if in_production:
            raise RepositoryUnavailableError(f"Connexion a MongoDB impossible : {exc}") from exc
        logger.warning("MongoDB injoignable (%s) : repli sur le stockage memoire.", exc)
        _resolved = True
        _repository = MemoryUserRepository()

    return _repository


def reset_repository(repository: UserRepository | None = None) -> None:
    """Remplace le depot. Reserve aux tests et au demarrage."""
    global _repository, _resolved
    _repository = repository
    _resolved = repository is not None
