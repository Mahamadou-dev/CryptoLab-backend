"""
Modeles Pydantic : validation des entrees de l'API et evenements de statistiques.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

# Bornes de securite communes. Elles evitent qu'une requete unique ne monopolise
# le serveur, et donnent des messages d'erreur clairs plutot qu'un timeout.
MAX_TEXT = 20_000
MAX_KEY = 512
MAX_PEM = 8_192
MAX_HEX = 40_000


# --- Statistiques anonymes ---------------------------------------------------

class UsageEvent(BaseModel):
    """
    Evenement d'usage anonyme. Ne contient JAMAIS de contenu utilisateur :
    ni texte clair, ni cle, ni resultat. Voir db/crud.py.
    """

    algorithm: str
    action: str  # encrypt | decrypt | hash | verify | simulate
    input_length: int = 0
    # default_factory : evalue a chaque instanciation. L'ancien
    # `datetime.now()` en valeur par defaut etait fige a l'import du module,
    # et tous les enregistrements portaient l'heure de demarrage du serveur.
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- Modeles d'entree (validation API) ---------------------------------------

class TextInput(BaseModel):
    """Texte simple (ex: SHA-256)."""

    text: str = Field(..., max_length=MAX_TEXT)


class ShiftInput(BaseModel):
    """Texte + entier. Utilise par Cesar (decalage) et Rail Fence (rails)."""

    text: str = Field(..., max_length=MAX_TEXT)
    shift: int = Field(..., ge=-1_000, le=1_000)


# Alias historique : l'ancien nom reste valide pour ne pas casser les imports.
CaesarInput = ShiftInput


class KeyTextInput(BaseModel):
    """Texte + cle (Vigenere, Playfair, transposition, DES, AES)."""

    text: str = Field(..., max_length=MAX_TEXT)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)


class BcryptVerifyInput(BaseModel):
    """Verification d'un hash bcrypt."""

    text: str = Field(..., max_length=MAX_KEY)
    hashed_text: str = Field(..., max_length=256)


class AesDecryptInput(BaseModel):
    """Dechiffrement AES-256-GCM."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    nonce_hex: str = Field(..., max_length=64)
    tag_hex: str = Field(..., max_length=64)


class DesDecryptInput(BaseModel):
    """Dechiffrement DES-CBC."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    iv_hex: str = Field(..., max_length=32)


class RsaEncryptInput(BaseModel):
    """Chiffrement RSA."""

    text: str = Field(..., max_length=190)  # limite OAEP/SHA-1 pour RSA-2048
    public_key: str = Field(..., max_length=MAX_PEM)


class RsaDecryptInput(BaseModel):
    """Dechiffrement RSA."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    private_key: str = Field(..., max_length=MAX_PEM)


# Alias historiques (AesInput/DesInput etaient des doublons de KeyTextInput).
AesInput = KeyTextInput
DesInput = KeyTextInput
