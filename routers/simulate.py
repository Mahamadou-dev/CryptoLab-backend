from fastapi import APIRouter, HTTPException, Body
from utils import step_visualizer, des_simulator, aes_simulator
from db.models import CaesarInput, KeyTextInput
import pydantic
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult
from datetime import datetime

router = APIRouter(prefix="/api/simulate", tags=["Simulation"])


@router.post("/{algo}", summary="Get step-by-step simulation for an algorithm")
async def simulate_algorithm(algo: str, data: dict = Body(...)):
    """
    Exécute une simulation étape par étape pour un algorithme donné
    ET sauvegarde le résultat dans la base de données.
    """

    simulation_result = None  # Initialise le conteneur de résultat

    if algo == "caesar":
        try:
            input_data = CaesarInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour César: {e}")
        simulation_result = step_visualizer.simulate_caesar_encrypt(input_data.text, input_data.shift)

    elif algo == "vigenere":
        try:
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour Vigenère: {e}")
        simulation_result = step_visualizer.simulate_vigenere_encrypt(input_data.text, input_data.key)

    elif algo == "playfair":
        try:
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour Playfair: {e}")
        simulation_result = step_visualizer.simulate_playfair_encrypt(input_data.text, input_data.key)

    elif algo == "des":
        try:
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour DES: {e}")
        simulation_result = des_simulator.simulate_des_encrypt(input_data.text, input_data.key)

    elif algo == "aes":
        try:
            input_data = KeyTextInput(**data)
        except pydantic.ValidationError as e:
            raise HTTPException(status_code=422, detail=f"Données invalides pour AES: {e}")
        simulation_result = aes_simulator.simulate_aes_encrypt(input_data.text, input_data.key)

    # --- GESTION DE LA SORTIE ET SAUVEGARDE ---
    if simulation_result:
        try:
            # 1. Créer l'objet à sauvegarder (si final_result existe)
            if simulation_result.get("final_result_hex"):  # Pour AES/DES
                output_text = simulation_result.get("final_result_hex")
            else:  # Pour les classiques
                output_text = simulation_result.get("final_result", "")

            result_to_save = SimulationResult(
                algorithm=algo,
                action="simulate",
                input_text=data.get("text", "[texte non fourni]"),
                output_text=output_text,
                timestamp=datetime.now()
            )
            # 2. Appeler la fonction de sauvegarde
            crud.save_result(result_to_save)
        except Exception as e:
            print(f"Erreur lors de la sauvegarde: {e}")  # Ne pas bloquer la simulation

        # 3. Retourner le résultat au frontend
        return {"algorithm": algo, **simulation_result}

    # Si on arrive ici, aucun 'if' n'a correspondu
    else:
        raise HTTPException(status_code=404,
                            detail=f"Algorithme '{algo}' non trouvé ou non supporté pour la simulation.")
