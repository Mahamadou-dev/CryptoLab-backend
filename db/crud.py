from .connection import get_db
from .models import SimulationResult # 1. Importer le modèle Pydantic

def save_result(data: SimulationResult): # 2. Utiliser le modèle comme type
    """
    Sauvegarde un objet SimulationResult validé dans la collection 'results'.
    """
    db = get_db()
    # 3. Convertir le modèle Pydantic en dictionnaire avant l'insertion
    return db.results.insert_one(data.model_dump())
