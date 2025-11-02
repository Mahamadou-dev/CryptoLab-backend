from pydantic import BaseModel
from datetime import datetime

# (Tu as déjà SimulationResult ici)
class SimulationResult(BaseModel):
    algorithm: str
    action: str   # encrypt / decrypt / hash
    input_text: str
    output_text: str
    timestamp: datetime = datetime.now() # Ajout d'une valeur par défaut

# --- Nouveaux modèles d'entrée ---

class TextInput(BaseModel):
    """ Modèle de base pour du texte simple """
    text: str

class CaesarInput(BaseModel):
    """ Modèle pour César """
    text: str
    shift: int

class KeyTextInput(BaseModel):
    """ Modèle générique pour texte + clé """
    text: str
    key: str


class BcryptVerifyInput(BaseModel):
    """ Modèle pour la vérification bcrypt """
    text: str
    hashed_text: str

class AesInput(BaseModel):
    """ Modèle pour le chiffrement AES """
    text: str
    key: str  # La phrase secrète (sera hachée en clé de 256 bits)

class AesDecryptInput(BaseModel):
    """
    Modèle pour le déchiffrement AES.
    On s'attend à recevoir les données en hexadécimal,
    car c'est le format le plus courant pour transporter des octets en JSON.
    """
    cipher_hex: str
    key: str
    nonce_hex: str
    tag_hex: str

class DesInput(BaseModel):
    """ Modèle pour le chiffrement DES """
    text: str
    key: str  # Phrase secrète (sera hachée en clé de 8 octets)

class DesDecryptInput(BaseModel):
    """ Modèle pour le déchiffrement DES-CBC """
    cipher_hex: str
    key: str
    iv_hex: str       # Le vecteur d'initialisation (IV) est requis

class RsaEncryptInput(BaseModel):
    """ Modèle pour le chiffrement RSA """
    text: str
    public_key: str  # La clé publique au format PEM (texte)

class RsaDecryptInput(BaseModel):
    """ Modèle pour le déchiffrement RSA """
    cipher_hex: str
    private_key: str # La clé privée au format PEM (texte)