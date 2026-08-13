"""
Logique metier de l'authentification : inscription, connexion, resolution du
porteur d'un jeton.

Le routeur se contente de traduire ces fonctions en HTTP.
"""

import logging
import time
from collections import defaultdict, deque

from auth import repository as repo
from auth.models import RegisterInput, UserPublic
from auth.security import create_token, hash_password, verify_password

logger = logging.getLogger(__name__)

# Hash bcrypt d'une valeur sans interet, verifie lorsqu'aucun compte ne
# correspond a l'e-mail donne. Sans lui, une connexion sur un e-mail inconnu
# repondrait nettement plus vite que sur un e-mail connu, et le temps de reponse
# suffirait a enumerer les comptes.
_DUMMY_HASH = hash_password("cryptolab-dummy-password")

# Limitation de debit des connexions : 10 tentatives par e-mail sur 5 minutes.
# Volontairement en memoire du processus — c'est un ralentisseur pedagogique,
# pas une defense anti-DDoS. Une vraie protection vit devant l'application.
_ATTEMPT_WINDOW = 300.0
_ATTEMPT_LIMIT = 10
_attempts: dict[str, deque[float]] = defaultdict(deque)


class AuthError(Exception):
    """Echec d'authentification, avec le code HTTP a renvoyer."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def to_public(document: dict) -> UserPublic:
    """Projette un document de base vers la vue publique (sans le hash)."""
    return UserPublic(
        id=document["_id"],
        email=document["email"],
        first_name=document["first_name"],
        last_name=document["last_name"],
        country=document["country"],
        city=document["city"],
        created_at=document["created_at"],
    )


def _store() -> repo.UserRepository:
    try:
        return repo.get_repository()
    except repo.RepositoryUnavailableError as exc:
        logger.error("Depot de comptes indisponible : %s", exc)
        raise AuthError(503, "Le service de comptes est momentanement indisponible.") from exc


def _rate_limit(email: str) -> None:
    """Refuse les tentatives au-dela du quota, et purge la fenetre glissante."""
    now = time.monotonic()
    window = _attempts[email]
    while window and now - window[0] > _ATTEMPT_WINDOW:
        window.popleft()
    if len(window) >= _ATTEMPT_LIMIT:
        raise AuthError(429, "Trop de tentatives de connexion. Reessayez dans quelques minutes.")
    window.append(now)


def reset_rate_limits() -> None:
    """Vide le compteur de tentatives. Reserve aux tests."""
    _attempts.clear()


def register(data: RegisterInput) -> tuple[str, int, UserPublic]:
    """Cree un compte et retourne (jeton, duree de vie, utilisateur public)."""
    store = _store()
    email = repo.normalise_email(data.email)

    if store.find_by_email(email) is not None:
        raise AuthError(409, "Un compte existe deja pour cette adresse e-mail.")

    document = repo.new_user_document(
        email=email,
        password_hash=hash_password(data.password),
        first_name=data.first_name,
        last_name=data.last_name,
        country=data.country,
        city=data.city,
    )

    try:
        created = store.create(document)
    except repo.DuplicateEmailError as exc:
        # Course entre deux inscriptions simultanees : c'est l'index unique de
        # MongoDB qui tranche, pas la verification faite plus haut.
        raise AuthError(409, "Un compte existe deja pour cette adresse e-mail.") from exc

    user = to_public(created)
    token, expires_in = create_token(user.id, user.email)
    return token, expires_in, user


def login(email: str, password: str) -> tuple[str, int, UserPublic]:
    """Verifie les identifiants et retourne (jeton, duree de vie, utilisateur)."""
    normalised = repo.normalise_email(email)
    _rate_limit(normalised)

    store = _store()
    document = store.find_by_email(normalised)

    if document is None:
        verify_password(password, _DUMMY_HASH)
        raise AuthError(401, "E-mail ou mot de passe incorrect.")

    if not verify_password(password, document["password_hash"]):
        raise AuthError(401, "E-mail ou mot de passe incorrect.")

    # Connexion reussie : le compteur repart de zero pour cet e-mail.
    _attempts.pop(normalised, None)

    user = to_public(document)
    token, expires_in = create_token(user.id, user.email)
    return token, expires_in, user


def user_from_token(token: str) -> UserPublic:
    """Resout le porteur d'un jeton, ou leve une AuthError 401."""
    from auth.security import decode_token

    payload = decode_token(token)
    if payload is None or not payload.get("sub"):
        raise AuthError(401, "Session invalide ou expiree.")

    document = _store().find_by_id(payload["sub"])
    if document is None:
        # Jeton valablement signe mais compte disparu (base reinitialisee,
        # compte supprime) : la session n'a plus de sens.
        raise AuthError(401, "Session invalide ou expiree.")

    return to_public(document)
