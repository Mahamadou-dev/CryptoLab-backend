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


class BcryptHashInput(BaseModel):
    """
    Hachage bcrypt avec facteur de cout reglable.

    `cost` est le logarithme du nombre de tours (2**cost) : chaque unite
    double le temps de calcul. Borne a 16 (~quelques secondes) pour qu'une
    requete ne monopolise pas le serveur.
    """

    text: str = Field(..., max_length=MAX_KEY)
    cost: int = Field(default=12, ge=4, le=16)


class HmacLengthExtensionInput(BaseModel):
    """Demonstration pedagogique de l'attaque par extension de longueur."""

    secret: str = Field(..., max_length=MAX_KEY)
    message: str = Field(..., max_length=MAX_TEXT)


class Pbkdf2Input(BaseModel):
    """Derivation PBKDF2 (RFC 8018)."""

    password: str = Field(..., max_length=MAX_KEY)
    salt_hex: str = Field(..., max_length=128)
    iterations: int = Field(default=200_000, ge=1, le=2_000_000)
    dklen: int = Field(default=32, ge=1, le=128)


class ScryptInput(BaseModel):
    """Derivation scrypt (RFC 7914)."""

    password: str = Field(..., max_length=MAX_KEY)
    salt_hex: str = Field(..., max_length=128)
    n: int = Field(default=16_384, ge=2, le=1_048_576)
    r: int = Field(default=8, ge=1, le=32)
    p: int = Field(default=1, ge=1, le=16)
    dklen: int = Field(default=32, ge=1, le=128)


class AesDecryptInput(BaseModel):
    """Dechiffrement AES-256-GCM."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    nonce_hex: str = Field(..., max_length=64)
    tag_hex: str = Field(..., max_length=64)
    salt_hex: str = Field(..., max_length=64)


class DesDecryptInput(BaseModel):
    """Dechiffrement DES-CBC."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    iv_hex: str = Field(..., max_length=32)
    salt_hex: str = Field(..., max_length=64)


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


class AesVariantDecryptInput(BaseModel):
    """Dechiffrement AES-GCM pour les variantes 128/192 bits (`AesDecryptInput` sert le 256 bits historique)."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    nonce_hex: str = Field(..., max_length=64)
    tag_hex: str = Field(..., max_length=64)
    salt_hex: str = Field(..., max_length=64)


class ChaCha20Input(BaseModel):
    """Chiffrement ChaCha20-Poly1305 (RFC 8439)."""

    text: str = Field(..., max_length=MAX_TEXT)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)


class ChaCha20DecryptInput(BaseModel):
    """Dechiffrement ChaCha20-Poly1305."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    nonce_hex: str = Field(..., max_length=32)
    salt_hex: str = Field(..., max_length=64)


class ModesEncryptInput(BaseModel):
    """
    Chiffrement pedagogique par bloc, cle et IV/nonce fournis en clair (hex).

    Couche pedagogique, pas production : la cle et l'IV sont explicites pour
    pouvoir rejouer des vecteurs NIST SP 800-38A/38D deterministes et illustrer
    la difference entre modes (le "pingouin ECB"). En production (`aes_tool`,
    `des_tool`), l'IV/le nonce sont toujours tires au hasard par le cipher.
    """

    key_hex: str = Field(..., max_length=64)
    plaintext_hex: str = Field(..., max_length=MAX_HEX)
    iv_hex: str = Field(default="", max_length=32)


class EcbPenguinInput(BaseModel):
    """Repete un bloc de 16 octets et compare la sortie ECB/CBC/CTR pour le meme motif."""

    key_hex: str = Field(..., max_length=64)
    block_hex: str = Field(..., max_length=32, min_length=32)
    repeats: int = Field(default=4, ge=2, le=32)


class Rc4Input(BaseModel):
    """RC4 (chiffrement de flot). Le meme code chiffre et dechiffre : XOR involutif."""

    text: str = Field(..., max_length=MAX_TEXT)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)


class Rc4HexInput(BaseModel):
    """RC4 sur une entree hexadecimale, pour rejouer les vecteurs RFC 6229 (flux non-UTF-8)."""

    plaintext_hex: str = Field(..., max_length=MAX_HEX)
    key_hex: str = Field(..., max_length=MAX_KEY)


class AesDecryptSimInput(BaseModel):
    """Dechiffrement pas a pas AES (simulateur pedagogique, cle en clair, pas de GCM)."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)


class DesDecryptSimInput(BaseModel):
    """Dechiffrement pas a pas DES (simulateur pedagogique)."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)


class TripleDesDecryptInput(BaseModel):
    """Dechiffrement 3DES-CBC."""

    cipher_hex: str = Field(..., max_length=MAX_HEX)
    key: str = Field(..., min_length=1, max_length=MAX_KEY)
    iv_hex: str = Field(..., max_length=16)
    salt_hex: str = Field(..., max_length=64)
