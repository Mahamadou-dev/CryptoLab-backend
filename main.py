import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.connection import stats_enabled
from registry import build_catalog_router, build_routers, registry
from registry.envelope import install_handlers
from routers import auth, simulate

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="CryptoLab API",
    version="2.0.0-dev",
    description=(
        "API pedagogique de CryptoLab.\n\n"
        "**Avertissement** : les implementations exposees ici sont ecrites pour "
        "etre lues et tracees, pas pour etre sures. Elles ne resistent pas aux "
        "attaques par canaux auxiliaires et ne doivent jamais proteger de "
        "vraies donnees.\n\n"
        "Aucune donnee saisie par l'utilisateur n'est enregistree."
    ),
)

# --- CORS ---
# Configurable par l'environnement : CRYPTOLAB_ALLOWED_ORIGINS="https://a,https://b"
DEFAULT_ORIGINS = "http://localhost:3000,https://cryptolaboratory.vercel.app"
origins = [
    origin.strip()
    for origin in os.getenv("CRYPTOLAB_ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    # L'API n'utilise ni cookie ni session : les identifiants sont inutiles.
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# --- Enveloppe de reponse ---
# Branche avant les routeurs : toute sortie de l'API, y compris les erreurs de
# validation que nous n'ecrivons pas nous-memes, respecte {ok, data, error}.
install_handlers(app)

# --- Routeurs derives du registre ---
# Les routes des algorithmes ne sont plus ecrites a la main : elles sont
# generees depuis registry/catalog/. Ajouter un algorithme = ajouter un fichier.
for algorithm_router in build_routers(registry):
    app.include_router(algorithm_router)
app.include_router(build_catalog_router(registry))

# --- Routeurs ecrits a la main ---
# La simulation pas a pas et l'authentification ne sont pas des algorithmes du
# catalogue : elles gardent leurs routeurs propres.
app.include_router(simulate.router)
app.include_router(auth.router)


@app.get("/", tags=["Meta"], summary="Health check")
def root():
    """Point d'entree racine : verifie que l'API est en ligne."""
    return {
        "message": "Bienvenue sur l'API CryptoLab !",
        "version": app.version,
        "docs": "/docs",
        "educational_only": True,
    }


@app.get("/health", tags=["Meta"], summary="Detailed health status")
def health():
    """Etat detaille, utile pour la supervision et la CI."""
    # Quel stockage porte reellement les comptes ? La question se pose a chaque
    # deploiement : un repli silencieux sur la memoire ferait disparaitre les
    # inscriptions au premier redemarrage.
    try:
        from auth.repository import MongoUserRepository, get_repository

        accounts = "mongodb" if isinstance(get_repository(), MongoUserRepository) else "memory"
    except Exception:
        accounts = "unavailable"

    return {
        "status": "ok",
        "anonymous_stats": stats_enabled(),
        "accounts_backend": accounts,
        "allowed_origins": origins,
    }
