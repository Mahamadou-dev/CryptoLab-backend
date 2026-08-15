"""
Enveloppe de reponse unique.

Toute reponse de l'API a exactement deux formes possibles :

    {"ok": true,  "data": {...},  "error": null}
    {"ok": false, "data": null,   "error": {"code": "...", "message": "...",
                                            "details": {...}}}

Le statut HTTP porte la meme information que `ok` — un client qui ne regarde que
le code retour a raison, et un client qui ne regarde que l'enveloppe aussi.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import CryptoLabError

T = TypeVar("T")


class ErrorBody(BaseModel):
    """Partie « erreur » de l'enveloppe."""

    code: str = Field(..., description="Code stable, destine aux programmes.")
    message: str = Field(..., description="Message lisible, destine aux etudiants.")
    details: dict[str, Any] = Field(default_factory=dict)


class Envelope(BaseModel, Generic[T]):
    """Enveloppe generique. `data` et `error` sont mutuellement exclusifs."""

    ok: bool
    data: T | None = None
    error: ErrorBody | None = None


def success(data: Any, status: int = 200) -> JSONResponse:
    """Reponse reussie."""
    return JSONResponse(
        status_code=status,
        content={"ok": True, "data": jsonable(data), "error": None},
    )


def failure(
    code: str,
    message: str,
    status: int,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Reponse en echec, avec le vrai code HTTP."""
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "data": None,
            "error": {"code": code, "message": message, "details": details or {}},
        },
    )


def jsonable(value: Any) -> Any:
    """Convertit les modeles Pydantic imbriques en structures JSON."""
    from fastapi.encoders import jsonable_encoder

    return jsonable_encoder(value)


#: Prefixes servis hors enveloppe.
#
# L'authentification garde le contrat `{"detail": ...}` de FastAPI. Ce n'est pas
# un oubli : c'est une frontiere. Ces routes ne sont pas consommees par un
# navigateur mais par les route handlers Next, qui les relaient en deposant un
# cookie httpOnly — un chemin de securite couvert par ses propres tests. Elles
# emettaient deja de vrais codes HTTP ; les envelopper changerait ce contrat
# sans rien corriger. L'enveloppe repond au probleme des routes d'algorithmes,
# qui renvoyaient « Erreur: ... » en 200 OK.
UNENVELOPED_PREFIXES = ("/api/auth",)


def _is_enveloped(request: Request) -> bool:
    return not request.url.path.startswith(UNENVELOPED_PREFIXES)


def install_handlers(app) -> None:
    """
    Branche les gestionnaires d'exceptions, pour que *toute* sortie de l'API
    respecte l'enveloppe — y compris les erreurs que nous n'avons pas ecrites.
    """
    from fastapi.exception_handlers import (
        http_exception_handler,
        request_validation_exception_handler,
    )

    @app.exception_handler(CryptoLabError)
    async def _crypto_error(_request: Request, exc: CryptoLabError):
        return failure(exc.code, exc.message, exc.status, exc.details)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        if not _is_enveloped(request):
            return await http_exception_handler(request, exc)

        # Les routeurs ecrits a la main (la simulation pas a pas) levent des
        # HTTPException. Elles passent par l'enveloppe comme le reste : un
        # client n'a jamais deux formats d'erreur a gerer.
        codes = {400: "invalid_input", 401: "unauthorized", 403: "forbidden",
                 404: "not_found", 409: "conflict", 429: "rate_limited"}
        detail = exc.detail
        return failure(
            codes.get(exc.status_code, "error"),
            detail if isinstance(detail, str) else "La requete n'a pas pu etre traitee.",
            exc.status_code,
            {} if isinstance(detail, str) else {"detail": jsonable(detail)},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        if not _is_enveloped(request):
            return await request_validation_exception_handler(request, exc)

        # Pydantic renvoie une liste d'erreurs structurees ; on la conserve dans
        # `details` et on resume la premiere dans `message`.
        errors = exc.errors()
        first = errors[0] if errors else {}
        field = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
        message = first.get("msg", "Donnees d'entree invalides.")
        return failure(
            "validation_error",
            f"{field} : {message}" if field else message,
            422,
            {"errors": jsonable(errors)},
        )
