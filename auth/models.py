"""Modeles Pydantic de l'authentification."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

# bcrypt tronque au-dela de 72 octets ; on borne en dessous pour que la limite
# soit franche cote validation plutot que silencieuse cote hachage.
MIN_PASSWORD = 10
MAX_PASSWORD = 72


def _clean(value: str) -> str:
    """Normalise un champ texte libre : espaces reduits, bords rognes."""
    return " ".join(value.split())


class RegisterInput(BaseModel):
    """Inscription : identite minimale, rien de plus que necessaire."""

    email: EmailStr
    password: str = Field(..., min_length=MIN_PASSWORD, max_length=MAX_PASSWORD)
    first_name: str = Field(..., min_length=1, max_length=80)
    last_name: str = Field(..., min_length=1, max_length=80)
    country: str = Field(..., min_length=2, max_length=80)
    city: str = Field(..., min_length=1, max_length=80)

    @field_validator("first_name", "last_name", "country", "city")
    @classmethod
    def _normalise(cls, value: str) -> str:
        cleaned = _clean(value)
        if not cleaned:
            raise ValueError("Ce champ ne peut pas etre vide.")
        return cleaned

    @field_validator("password")
    @classmethod
    def _password_bytes(cls, value: str) -> str:
        # min_length/max_length comptent des caracteres ; bcrypt compte des
        # octets. Un mot de passe en arabe ou en emoji peut passer la validation
        # Pydantic et depasser la limite de bcrypt.
        if len(value.encode("utf-8")) > MAX_PASSWORD:
            raise ValueError(f"Le mot de passe depasse {MAX_PASSWORD} octets.")
        if value.strip() != value:
            raise ValueError("Le mot de passe ne peut ni commencer ni finir par un espace.")
        return value


class LoginInput(BaseModel):
    """Connexion."""

    email: EmailStr
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD * 2)


class UserPublic(BaseModel):
    """
    Vue publique d'un utilisateur. C'est le SEUL modele renvoye au client :
    il ne contient ni hash de mot de passe, ni donnee interne.
    """

    id: str
    email: EmailStr
    first_name: str
    last_name: str
    country: str
    city: str
    created_at: datetime


class AuthResponse(BaseModel):
    """Reponse d'inscription et de connexion."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPublic
