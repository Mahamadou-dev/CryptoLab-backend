from pydantic import BaseModel
from datetime import datetime

class SimulationResult(BaseModel):
    """
    Le modèle pour les données que nous stockons dans MongoDB.
    """
    algorithm: str
    action: str   # encrypt / decrypt / hash / simulate
    input_text: str
    output_text: str
    timestamp: datetime = datetime.now()

# --- Modèles d'Entrée (Validation API) ---

class TextInput(BaseModel):
    """ Modèle de base pour du texte simple (ex: SHA-256) """
    text: str

class CaesarInput(BaseModel):
    """ Modèle spécifique pour César """
    text: str
    shift: int

class KeyTextInput(BaseModel):
    """
    Modèle générique pour les algos nécessitant un texte et une clé.
    (Utilisé pour Vigenère, Playfair, DES, AES)
    """
    text: str
    key: str

class BcryptVerifyInput(BaseModel):
    """ Modèle pour la vérification bcrypt """
    text: str
    hashed_text: str

class AesInput(BaseModel):
    """
    Modèle pour le chiffrement AES.
    Note: Il utilise KeyTextInput car les champs sont identiques.
    """
    text: str
    key: str

class AesDecryptInput(BaseModel):
    """ Modèle pour le déchiffrement AES-GCM """
    cipher_hex: str
    key: str
    nonce_hex: str
    tag_hex: str

class DesInput(BaseModel):
    """
    Modèle pour le chiffrement DES.
    Note: Il utilise KeyTextInput car les champs sont identiques.
    """
    text: str
    key: str

class DesDecryptInput(BaseModel):
    """ Modèle pour le déchiffrement DES-CBC """
    cipher_hex: str
    key: str
    iv_hex: str

class RsaEncryptInput(BaseModel):
    """ Modèle pour le chiffrement RSA """
    text: str
    public_key: str

class RsaDecryptInput(BaseModel):
    """ Modèle pour le déchiffrement RSA """
    cipher_hex: str
    private_key: str
