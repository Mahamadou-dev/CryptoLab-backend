"""
Simulations pas a pas.

Le dispatch passe desormais par une table plutot que par une cascade de `if`.
C'est la premiere marche vers le registre d'algorithmes prevu en phase 2 :
ajouter une simulation = ajouter une ligne.
"""

import logging
from collections.abc import Callable
from typing import Any

import pydantic
from fastapi import APIRouter, Body, HTTPException

from db import crud
from db.models import KeyTextInput, ShiftInput, TextInput
from registry.envelope import success
from utils import aes_simulator, des_simulator, step_visualizer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/simulate", tags=["Simulation"])


# algo -> (modele d'entree, fonction de simulation, extracteur d'arguments)
SIMULATORS: dict[str, tuple[type[pydantic.BaseModel], Callable[..., dict], Callable]] = {
    "caesar": (
        ShiftInput,
        step_visualizer.simulate_caesar_encrypt,
        lambda d: (d.text, d.shift),
    ),
    "vigenere": (
        KeyTextInput,
        step_visualizer.simulate_vigenere_encrypt,
        lambda d: (d.text, d.key),
    ),
    "playfair": (
        KeyTextInput,
        step_visualizer.simulate_playfair_encrypt,
        lambda d: (d.text, d.key),
    ),
    "railfence": (
        ShiftInput,
        step_visualizer.simulate_rail_fence_encrypt,
        lambda d: (d.text, d.shift),
    ),
    "columnar": (
        KeyTextInput,
        step_visualizer.simulate_columnar_encrypt,
        lambda d: (d.text, d.key),
    ),
    "des": (
        KeyTextInput,
        des_simulator.simulate_des_encrypt,
        lambda d: (d.text, d.key),
    ),
    "aes": (
        KeyTextInput,
        aes_simulator.simulate_aes_encrypt,
        lambda d: (d.text, d.key),
    ),
    "sha256": (
        TextInput,
        step_visualizer.simulate_sha256,
        lambda d: (d.text,),
    ),
    "sha1": (
        TextInput,
        step_visualizer.simulate_sha1,
        lambda d: (d.text,),
    ),
}


@router.get("", summary="List the algorithms available for simulation")
def list_simulations():
    return success({"algorithms": sorted(SIMULATORS)})


@router.post("/{algo}", summary="Get step-by-step simulation for an algorithm")
def simulate_algorithm(algo: str, data: dict = Body(...)) -> dict[str, Any]:
    """
    Execute une simulation etape par etape pour l'algorithme demande.

    Aucune donnee utilisateur n'est enregistree : seul un compteur d'usage
    anonyme est incremente.
    """
    entry = SIMULATORS.get(algo)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Algorithme '{algo}' non supporte pour la simulation. "
                f"Disponibles : {', '.join(sorted(SIMULATORS))}."
            ),
        )

    model, simulate, extract = entry

    try:
        parsed = model(**data)
    except pydantic.ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Donnees d'entree invalides pour '{algo}' : {exc.errors()}",
        ) from exc

    try:
        result = simulate(*extract(parsed))
    except Exception as exc:
        # On journalise la trace complete cote serveur, mais on ne renvoie
        # jamais le detail interne au client.
        logger.exception("Echec de la simulation '%s'", algo)
        raise HTTPException(
            status_code=500,
            detail=f"Erreur interne pendant la simulation de '{algo}'.",
        ) from exc

    crud.record_usage(algo, "simulate", len(parsed.text))
    return success({"algorithm": algo, **result})
