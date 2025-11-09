from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import classical, hash, modern, asymmetric, simulate

app = FastAPI(title="CryptoLab API", version="1.0")

# --- Configuration CORS ---
origins = [
    "http://localhost:3000",
    "https://cryptolaboratory.vercel.app"  # <-- CORRECTION : Remplacement par la bonne URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Autorise GET, POST, etc.
    allow_headers=["*"],
)

# --- Inclusion des Routeurs ---
app.include_router(classical.router)
app.include_router(hash.router)
app.include_router(modern.router)
app.include_router(asymmetric.router)
app.include_router(simulate.router)

@app.get("/")
def root():
    """
    Point d'entrée racine pour vérifier que l'API est en ligne.
    """
    return {"message": "Bienvenue sur l'API CryptoLab!"}