"""
Primitives de securite de l'authentification : hachage des mots de passe et
jetons JWT.

Contrairement a `utils/`, ce module ne fait aucune pedagogie : il delegue a
bcrypt et PyJWT, et rien d'autre.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"

# Duree de vie du jeton. 24h : assez long pour une seance de TP, assez court
# pour limiter la fenetre de compromission d'un jeton vole. Le choix precedent
# (7 jours) rendait la session quasi permanente du point de vue d'un
# utilisateur qui revient chaque jour sans jamais voir d'expiration.
TOKEN_TTL = timedelta(hours=int(os.getenv("CRYPTOLAB_JWT_TTL_HOURS", "24")))

# bcrypt tronque silencieusement au-dela de 72 octets : on refuse plutot que de
# laisser croire qu'un mot de passe de 200 caracteres est integralement pris en
# compte.
MAX_PASSWORD_BYTES = 72


class AuthConfigError(RuntimeError):
    """Configuration d'authentification invalide."""


def _load_secret() -> str:
    """
    Recupere le secret de signature.

    En production (CRYPTOLAB_ENV=production) son absence est une erreur fatale :
    un secret genere au demarrage invaliderait tous les jetons a chaque
    redemarrage, et differerait entre deux instances. En developpement, on en
    genere un ephemere pour que `uvicorn main:app` fonctionne sans configuration.
    """
    secret = os.getenv("CRYPTOLAB_JWT_SECRET", "").strip()
    if secret:
        return secret

    if os.getenv("CRYPTOLAB_ENV", "development").strip().lower() == "production":
        raise AuthConfigError(
            "CRYPTOLAB_JWT_SECRET est absent alors que CRYPTOLAB_ENV=production. "
            "Generez-le avec : python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )

    logger.warning(
        "CRYPTOLAB_JWT_SECRET absent : secret ephemere genere pour le "
        "developpement. Les sessions seront perdues au redemarrage."
    )
    return secrets.token_urlsafe(64)


_SECRET = _load_secret()


# --- Mots de passe ------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hache un mot de passe avec bcrypt (sel aleatoire inclus dans le hash)."""
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Le mot de passe depasse {MAX_PASSWORD_BYTES} octets, "
            "limite de bcrypt."
        )
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """
    Compare un mot de passe a son hash. Ne leve jamais : un hash corrompu en
    base doit se traduire par un refus, pas par une erreur 500.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- Jetons -------------------------------------------------------------------

def create_token(subject: str, email: str) -> tuple[str, int]:
    """
    Signe un jeton d'acces.

    Returns:
        (jeton, duree de vie en secondes)
    """
    now = datetime.now(timezone.utc)
    expires = now + TOKEN_TTL
    payload = {
        "sub": subject,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    token = jwt.encode(payload, _SECRET, algorithm=ALGORITHM)
    return token, int(TOKEN_TTL.total_seconds())


def decode_token(token: str) -> dict | None:
    """Retourne la charge utile du jeton, ou None s'il est invalide ou expire."""
    try:
        return jwt.decode(token, _SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
