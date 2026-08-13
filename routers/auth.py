"""
Routes d'authentification.

    POST /api/auth/register   inscription (e-mail, mot de passe, identite, lieu)
    POST /api/auth/login      connexion
    GET  /api/auth/me         profil du porteur du jeton

Le jeton est renvoye dans le corps de la reponse. C'est le frontend Next.js qui
le range dans un cookie httpOnly de son propre domaine (voir app/api/auth/), de
sorte qu'aucun script de page ne puisse le lire.
"""

from fastapi import APIRouter, Depends, HTTPException, Request

from auth import service
from auth.models import AuthResponse, LoginInput, RegisterInput, UserPublic

router = APIRouter(prefix="/api/auth", tags=["Authentification"])


def _http(error: service.AuthError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=error.detail)


def current_user(request: Request) -> UserPublic:
    """
    Dependance FastAPI : resout l'utilisateur a partir de l'en-tete
    `Authorization: Bearer <jeton>`.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")

    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Jeton manquant.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return service.user_from_token(token.strip())
    except service.AuthError as error:
        raise _http(error) from error


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=201,
    summary="Creer un compte",
)
def register_route(data: RegisterInput):
    try:
        token, expires_in, user = service.register(data)
    except service.AuthError as error:
        raise _http(error) from error
    return AuthResponse(access_token=token, expires_in=expires_in, user=user)


@router.post("/login", response_model=AuthResponse, summary="Se connecter")
def login_route(data: LoginInput):
    try:
        token, expires_in, user = service.login(data.email, data.password)
    except service.AuthError as error:
        raise _http(error) from error
    return AuthResponse(access_token=token, expires_in=expires_in, user=user)


@router.get("/me", response_model=UserPublic, summary="Profil courant")
def me_route(user: UserPublic = Depends(current_user)):
    return user
