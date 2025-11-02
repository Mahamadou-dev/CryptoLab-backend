from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # 1. Importer le middleware CORS
from routers import classical, hash, modern, asymmetric, simulate

app = FastAPI(title="CryptoLab API", version="1.0")

# 2. Définir les "origines" (clients) autorisées
# Ce sont les URL de frontend qui ont le droit de parler à ton API
origins = [
    "http://localhost:3000",  # Pour ton développement local
    # "https://ton-futur-site.vercel.app", # Tu ajouteras ton URL Vercel ici plus tard
]

# 3. Ajouter le middleware à ton application
# C'est la partie qui dit "Oui, localhost:3000 a le droit de me parler"
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Autorise toutes les méthodes (GET, POST, etc.)
    allow_headers=["*"],  # Autorise tous les en-têtes
)

# Inclure tous les routeurs
app.include_router(classical.router)
app.include_router(hash.router)
app.include_router(modern.router)
app.include_router(asymmetric.router)
app.include_router(simulate.router)

@app.get("/")
def root():
    return {"message": "CryptoLab API running!"}