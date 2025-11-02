from fastapi import APIRouter, HTTPException, Body
from utils import step_visualizer, des_simulator,aes_simulator
from db.models import CaesarInput, KeyTextInput  # On réutilise nos modèles Pydantic
import pydantic

router = APIRouter(prefix="/api/simulate", tags=["Simulation"])


@router.post("/{algo}", summary="Get step-by-step simulation for an algorithm")
async def simulate_algorithm(algo: str, data: dict = Body(...)):
    """
    Exécute une simulation étape par étape pour un algorithme donné.

    - **algo**: Le nom de l'algorithme (ex: "caesar", "vigenere").
    - **data**: Le corps de la requête contenant les paramètres
      nécessaires (ex: 'text', 'shift', 'key').
    """

    if algo == "caesar":
        try:
            # Valider les données reçues avec notre modèle Pydantic
            input_data = CaesarInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour César: {e}")

        # Appeler la fonction de simulation
        simulation = step_visualizer.simulate_caesar_encrypt(
            input_data.text,
            input_data.shift
        )
        return {"algorithm": "caesar", **simulation}
    elif algo == "vigenere":
        try:
            # Valider les données avec KeyTextInput
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour Vigenère: {e}")

        # Appeler la nouvelle fonction de simulation
        simulation = step_visualizer.simulate_vigenere_encrypt(
            input_data.text,
            input_data.key
        )
        return {"algorithm": "vigenere", **simulation}


    elif algo == "playfair":
        try:
            # Playfair utilise aussi un texte et une clé
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour Playfair: {e}")

        simulation = step_visualizer.simulate_playfair_encrypt(
            input_data.text,
            input_data.key
        )
        return {"algorithm": "playfair", **simulation}

    elif algo == "des":
        try:
            # DES utilise aussi un texte (8 chars) et une clé (8 chars)
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour DES: {e}")

        # Appel de la fonction principale du simulateur DES
        simulation = des_simulator.simulate_des_encrypt(
            input_data.text,
            input_data.key
        )
        return {"algorithm": "des", **simulation}

    elif algo == "aes":
        try:
            # AES-128 utilise un texte (16 chars) et une clé (16 chars)
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour AES: {e}")

        # Appel de la fonction principale du simulateur AES
        simulation = aes_simulator.simulate_aes_encrypt(
            input_data.text,
            input_data.key
        )
        return {"algorithm": "aes", **simulation}

    else:
        raise HTTPException(status_code=404,
                            detail=f"Algorithme '{algo}' non trouvé ou non supporté pour la simulation.")