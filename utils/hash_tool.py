import hashlib
import hmac
import time

import bcrypt

from utils.sha1_tool import sha1_from_scratch

# Cout bcrypt par defaut. 12 est la recommandation OWASP courante : assez lent
# pour decourager le brute force hors ligne, assez rapide pour rester utilisable
# dans un formulaire de connexion (quelques centaines de ms).
DEFAULT_BCRYPT_COST = 12


def hash_sha256(text: str) -> str:
    """
    Génère le hash SHA-256 d'un texte.
    L'entrée de hashlib doit être en bytes.
    """
    sha = hashlib.sha256(text.encode('utf-8'))
    return sha.hexdigest()


def hash_bcrypt(text: str, cost: int = DEFAULT_BCRYPT_COST) -> str:
    """
    Génère un hash bcrypt (avec salt) pour un texte.
    Retourne le hash en tant que chaîne de caractères (str).

    `cost` est le facteur de travail (rounds = 2**cost) : chaque incrément
    double le temps de calcul. C'est le levier qui garde bcrypt lent face aux
    GPU/ASIC des attaquants, malgre l'acceleration materielle qui augmente
    chaque annee.
    """
    text_bytes = text.encode('utf-8')
    salt = bcrypt.gensalt(rounds=cost)
    hashed_bytes = bcrypt.hashpw(text_bytes, salt)
    return hashed_bytes.decode('utf-8')


def verify_bcrypt(text: str, hashed_text: str) -> bool:
    """
    Vérifie si un texte en clair correspond à un hash bcrypt existant.
    """
    try:
        text_bytes = text.encode('utf-8')
        hashed_bytes = hashed_text.encode('utf-8')
        return bcrypt.checkpw(text_bytes, hashed_bytes)
    except Exception:
        return False


def time_bcrypt(text: str, cost: int) -> float:
    """Chronometre un hachage bcrypt a un cout donne, en secondes."""
    start = time.perf_counter()
    hash_bcrypt(text, cost=cost)
    return time.perf_counter() - start


# --- MD5 et SHA-1 : casses, conserves pour l'histoire -------------------------
# Maturity.BROKEN dans le registre : ni l'un ni l'autre ne doit proteger de
# vraies donnees. MD5 delegue a hashlib (aucun interet pedagogique a le
# reimplementer, sa structure est proche de SHA-1) ; SHA-1 a sa version
# "depuis zero" dans sha1_tool.py pour la trace pas a pas.

def hash_md5(text: str) -> str:
    """
    MD5 (RFC 1321). Collisions pratiques connues depuis 2004 (Wang et al.) :
    on sait construire deux messages differents de meme empreinte en quelques
    secondes sur un PC. A ne plus jamais utiliser pour l'integrite ou les mots
    de passe.
    """
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def hash_sha1(text: str) -> str:
    """
    SHA-1 (FIPS 180-1 / RFC 3174). Casse pratiquement en 2017 : l'attaque
    SHAttered (Stevens et al., Google/CWI) a produit deux PDF distincts
    partageant la meme empreinte SHA-1 (https://shattered.io/). Depuis, git,
    les navigateurs et les autorites de certification l'ont abandonne comme
    fonction de securite.
    """
    return hashlib.sha1(text.encode('utf-8')).hexdigest()


def hash_sha1_from_scratch(text: str) -> str:
    """Meme resultat que `hash_sha1`, mais recalcule depuis zero (pedagogie)."""
    return sha1_from_scratch(text.encode('utf-8'))


# --- SHA-3 / Keccak et BLAKE2 --------------------------------------------------

def hash_sha3_256(text: str) -> str:
    """
    SHA-3-256 (FIPS 202), construction eponge Keccak. Standardise en reponse
    au concours SHA-3 du NIST (2007-2012), independant de la famille
    Merkle-Damgard de SHA-1/SHA-256 — une attaque qui casserait l'une ne casse
    pas structurellement l'autre.
    """
    return hashlib.sha3_256(text.encode('utf-8')).hexdigest()


def hash_blake2b(text: str) -> str:
    """
    BLAKE2b (RFC 7693). Plus rapide que SHA-2/SHA-3 en logiciel, sans
    compromis de securite connu : finaliste du concours SHA-3, retenu par
    exemple par WireGuard et par le hachage de fichiers d'Argon2.
    """
    return hashlib.blake2b(text.encode('utf-8')).hexdigest()


# --- HMAC : authentification, pas seulement integrite --------------------------

def hmac_sha256(key: str, text: str) -> str:
    """
    HMAC-SHA256 (RFC 2104 / FIPS 198-1).

    Un hash nu (SHA-256(cle || message)) est vulnerable a l'attaque par
    extension de longueur : a partir de H(secret || message) et de la longueur
    du secret, un attaquant peut calculer H(secret || message || padding ||
    extra) SANS connaitre le secret, a cause de la structure Merkle-Damgard
    (l'etat final d'un hash est exactement l'etat initial du suivant). HMAC
    s'en protege en hachant la cle deux fois, avec deux bourrages distincts
    (RFC 2104) :

        HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

    Le hachage externe recoit un condense (H(...ipad...m)), jamais la cle en
    clair suivie du message : il n'y a plus d'etat interne exploitable par
    extension.
    """
    return hmac.new(key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_hmac_sha256(key: str, text: str, expected_hex: str) -> bool:
    """Comparaison a temps constant : ne jamais utiliser `==` sur un MAC."""
    computed = hmac.new(key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256).digest()
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    return hmac.compare_digest(computed, expected)


def demonstrate_length_extension_vulnerability(secret: str, message: str) -> dict:
    """
    Montre, sur un hash nu (pas HMAC), que `SHA256(secret || message)` change
    de facon previsible quand on ajoute des donnees a la fin — sans connaitre
    `secret` — pourvu qu'on connaisse sa longueur. C'est purement illustratif :
    la nouvelle empreinte est recalculee ici avec le vrai secret pour la
    comparaison, un attaquant reel utiliserait l'etat interne de hashlib
    (via des bibliotheques comme `hashpumpy`) plutot que le secret.
    """
    original = hashlib.sha256((secret + message).encode('utf-8')).hexdigest()
    extra = "&admin=true"
    extended = hashlib.sha256((secret + message + extra).encode('utf-8')).hexdigest()
    return {
        "original_hash": original,
        "extended_hash": extended,
        "note": (
            "Un hash nu ne protege pas contre l'ajout de donnees en fin de "
            "message : HMAC empeche precisement cette attaque."
        ),
    }


# --- Derivation de cles : PBKDF2 et scrypt --------------------------------------
# Le point commun : etirer une cle utilisateur (mot de passe, phrase secrete)
# faible en entropie vers une cle de la bonne taille, en rendant le calcul
# couteux pour ralentir la recherche exhaustive. Un simple SHA-256(mot_de_passe)
# n'a NI sel (deux utilisateurs avec le meme mot de passe ont le meme hash,
# et une table arc-en-ciel precalculee casse tout le monde a la fois) NI
# etirement (un GPU calcule des milliards de SHA-256 par seconde).

def pbkdf2_derive(
    password: str,
    salt: bytes,
    iterations: int = 200_000,
    dklen: int = 32,
    hash_name: str = "sha256",
) -> bytes:
    """
    PBKDF2 (RFC 8018, anciennement PKCS#5 v2 / RFC 2898). Applique HMAC en
    boucle `iterations` fois : le cout est purement CPU, ce qui le rend
    vulnerable aux GPU/ASIC (des milliers de coeurs en parallele) — c'est la
    faiblesse que scrypt et Argon2 corrigent en exigeant aussi de la memoire.
    """
    return hashlib.pbkdf2_hmac(hash_name, password.encode('utf-8'), salt, iterations, dklen)


def scrypt_derive(
    password: str,
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    dklen: int = 32,
) -> bytes:
    """
    scrypt (RFC 7914). `n` est le cout memoire (une table de `n` blocs de
    `128*r` octets doit rester accessible pendant le calcul), `r` la taille de
    bloc, `p` le parallelisme. Paralleliser une attaque scrypt sur GPU coute
    donc aussi de la memoire GPU, pas seulement du temps de calcul — c'est
    l'ecart avec PBKDF2 qu'il comble.
    """
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
