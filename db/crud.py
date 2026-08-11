"""
Statistiques d'usage ANONYMES.

Ce module remplace l'ancien `save_result`, qui ecrivait le texte clair et le
resultat de chaque operation dans MongoDB — y compris pour RSA et AES.

Regle absolue : rien de ce qu'un utilisateur saisit ne quitte la memoire du
processus. On n'enregistre que le nom de l'algorithme, l'action demandee et la
taille de l'entree, afin de savoir quels chapitres sont les plus utilises.
"""

import logging

from .connection import get_db
from .models import UsageEvent

logger = logging.getLogger(__name__)


def record_usage(algorithm: str, action: str, input_length: int = 0) -> None:
    """
    Enregistre un evenement d'usage anonyme. Silencieux et non bloquant :
    une panne de base ne doit jamais faire echouer une requete utilisateur.

    Args:
        algorithm: identifiant de l'algorithme (ex: "aes-gcm").
        action: "encrypt" | "decrypt" | "hash" | "verify" | "simulate".
        input_length: longueur de l'entree, en caracteres. JAMAIS le contenu.
    """
    db = get_db()
    if db is None:
        return

    try:
        event = UsageEvent(
            algorithm=algorithm,
            action=action,
            input_length=max(0, int(input_length)),
        )
        db.usage_events.insert_one(event.model_dump())
    except Exception as exc:  # pragma: no cover - depend de l'environnement
        logger.warning("Echec de l'enregistrement des statistiques : %s", exc)
