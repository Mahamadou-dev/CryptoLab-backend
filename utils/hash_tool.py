import hashlib
import bcrypt


def hash_sha256(text: str) -> str:
    """
    Génère le hash SHA-256 d'un texte.
    L'entrée de hashlib doit être en bytes.
    """
    sha = hashlib.sha256(text.encode('utf-8'))
    return sha.hexdigest()


def hash_bcrypt(text: str) -> str:
    """
    Génère un hash bcrypt (avec salt) pour un texte.
    Retourne le hash en tant que chaîne de caractères (str).
    """
    # bcrypt s'attend à des bytes
    text_bytes = text.encode('utf-8')
    # 1. Générer un salt
    salt = bcrypt.gensalt()
    # 2. Hacher le mot de passe
    hashed_bytes = bcrypt.hashpw(text_bytes, salt)
    # 3. Décoder en string pour le stockage/retour JSON
    return hashed_bytes.decode('utf-8')


def verify_bcrypt(text: str, hashed_text: str) -> bool:
    """
    Vérifie si un texte en clair correspond à un hash bcrypt existant.
    """
    try:
        text_bytes = text.encode('utf-8')
        hashed_bytes = hashed_text.encode('utf-8')

        # bcrypt.checkpw gère l'extraction du salt depuis le 'hashed_text'
        # et compare les deux.
        return bcrypt.checkpw(text_bytes, hashed_bytes)
    except Exception:
        # Gère les cas où le hash est mal formaté ou invalide
        return False