import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "cryptolab")

# Gère le cas où MONGO_URI n'est pas défini
if not MONGO_URI:
    print("Erreur: La variable d'environnement MONGO_URI n'est pas définie.")
    client = None
    db = None
else:
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        # Teste la connexion
        client.server_info()
        print(f"Connecté à MongoDB (Base: {DB_NAME})")
    except Exception as e:
        print(f"Erreur de connexion à MongoDB: {e}")
        client = None
        db = None

def get_db():
    if db is None:
        raise Exception("La connexion à la base de données n'est pas établie.")
    return db
