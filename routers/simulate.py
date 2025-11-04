from fastapi import APIRouter, HTTPException, Body
from utils import step_visualizer, des_simulator, aes_simulator
from db.models import CaesarInput, KeyTextInput
import pydantic
# --- AMÉLIORATION (Stockage) ---
from db import crud
from db.models import SimulationResult  # <-- Importation directe
from datetime import datetime

router = APIRouter(prefix="/api/simulate", tags=["Simulation"])


@router.post("/{algo}", summary="Get step-by-step simulation for an algorithm")
async def simulate_algorithm(algo: str, data: dict = Body(...)):
    """
    Exécute une simulation étape par étape pour un algorithme donné
    ET sauvegarde le résultat dans la base de données.
    """

    simulation_result = None  # Conteneur pour le résultat de la simulation
    input_data = None  # Conteneur pour les données d'entrée validées

    try:
        if algo == "caesar":
            input_data = CaesarInput(**data)
            simulation_result = step_visualizer.simulate_caesar_encrypt(input_data.text, input_data.shift)

        elif algo == "vigenere":
            input_data = KeyTextInput(**data)
            simulation_result = step_visualizer.simulate_vigenere_encrypt(input_data.text, input_data.key)

        elif algo == "playfair":
            input_data = KeyTextInput(**data)
            simulation_result = step_visualizer.simulate_playfair_encrypt(input_data.text, input_data.key)

        elif algo == "des":
            input_data = KeyTextInput(**data)
            simulation_result = des_simulator.simulate_des_encrypt(input_data.text, input_data.key)

        elif algo == "aes":
            input_data = KeyTextInput(**data)
            simulation_result = aes_simulator.simulate_aes_encrypt(input_data.text, input_data.key)

        # --- CORRECTION DU BLOC RAILFENCE ---
        elif algo == "railfence":
            # Réutilise CaesarInput (text, int) pour (text, depth)
            input_data = CaesarInput(**data)

            # --- CORRECTION (faute de frappe) ---
            # simulate_rail__fence_encrypt (2 underscores) -> simulate_rail_fence_encrypt (1 underscore)
            simulation_result = step_visualizer.simulate_rail_fence_encrypt(
                input_data.text,
                input_data.shift
            )
            # --- FIN DE LA CORRECTION ---

        else:
            # Si aucun 'if' ne correspond, l'algo n'est pas supporté
            raise HTTPException(status_code=404,
                                detail=f"Algorithme '{algo}' non trouvé ou non supporté pour la simulation.")

    except pydantic.ValidationError as e:
        # Gère toutes les erreurs de validation Pydantic
        raise HTTPException(status_code=422, detail=f"Données d'entrée invalides pour '{algo}': {e}")
    except Exception as e:
        # Gère les erreurs internes pendant la simulation (ex: bug dans playfair)
        raise HTTPException(status_code=500, detail=f"Erreur de simulation interne pour '{algo}': {str(e)}")

    # --- GESTION DE LA SORTIE ET SAUVEGARDE (MAINTENANT 100% UNIFIÉE) ---
    if simulation_result and input_data:
        try:
            # 1. Déterminer quel champ de résultat utiliser
            if "final_result_hex" in simulation_result:  # Pour AES/DES
                output_text = simulation_result.get("final_result_hex", "")
            else:  # Pour les classiques
                output_text = simulation_result.get("final_result", "")

            # 2. Créer l'objet à sauvegarder (en utilisant input_data.text)
            result_to_save = SimulationResult(
                algorithm=algo,
                action="simulate",
                input_text=input_data.text,
                output_text=output_text,
                timestamp=datetime.now()
            )
            # 3. Appeler la fonction de sauvegarde
            crud.save_result(result_to_save)

        except Exception as e:
            # Si la sauvegarde échoue, on l'affiche côté serveur
            # mais on NE bloque PAS l'utilisateur.
            print(f"CRITICAL: Échec de la sauvegarde BDD pour {algo}: {e}")

        # 4. Retourner le résultat au frontend
        return {"algorithm": algo, **simulation_result}

    # Si 'simulation_result' ou 'input_data' est None, c'est une erreur 404
    raise HTTPException(status_code=404,
                        detail=f"Algorithme '{algo}' non trouvé ou non supporté pour la simulation.")

