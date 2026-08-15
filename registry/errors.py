"""
Erreurs typees du registre.

Avant la v2, un echec de dechiffrement revenait au client en `200 OK` avec la
chaine `"Erreur: ..."` dans le champ resultat, et l'appelant la reperait par
`if "Erreur:" in plain_text`. Un texte dechiffre contenant le mot « Erreur: »
cassait donc le contrat, et aucun client HTTP standard ne pouvait distinguer un
succes d'un echec.

Chaque erreur porte desormais un code stable, destine aux programmes, et un
message en francais, destine aux etudiants.
"""

from __future__ import annotations


class CryptoLabError(Exception):
    """Erreur metier renvoyee au client sous forme d'enveloppe."""

    #: Code stable, lisible par un programme. Ne change jamais.
    code: str = "internal_error"
    #: Statut HTTP correspondant.
    status: int = 500

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidInput(CryptoLabError):
    """Entree syntaxiquement valide mais refusee par l'algorithme."""

    code = "invalid_input"
    status = 400


class InvalidKey(CryptoLabError):
    """Cle absente, malformee, ou de longueur incorrecte."""

    code = "invalid_key"
    status = 400


class DecryptionFailed(CryptoLabError):
    """
    Le dechiffrement a echoue.

    Cas pedagogiquement central : sur un mode authentifie comme AES-GCM, c'est
    la verification du tag qui echoue, et l'on ne peut pas distinguer « mauvaise
    cle » de « donnees alterees ». Le message le dit plutot que de le masquer.
    """

    code = "decryption_failed"
    status = 400


class UnknownAlgorithm(CryptoLabError):
    """Aucun algorithme de ce nom dans le registre."""

    code = "unknown_algorithm"
    status = 404


class UnsupportedOperation(CryptoLabError):
    """L'algorithme existe mais ne declare pas cette operation."""

    code = "unsupported_operation"
    status = 404
