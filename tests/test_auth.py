"""
Tests de l'authentification.

Ils tournent entierement sur le depot en memoire : aucun test ne touche au
cluster Atlas, et la suite reste executable hors ligne.
"""

import pytest

from auth import repository as repo
from auth import service
from auth.security import create_token, decode_token, hash_password, verify_password

VALID = {
    "email": "Alice@Example.COM",
    "password": "correct horse battery",
    "first_name": "Alice",
    "last_name": "Diallo",
    "country": "Niger",
    "city": "Niamey",
}


@pytest.fixture(autouse=True)
def memory_store():
    """Depot vierge avant chaque test, quotas de connexion remis a zero."""
    store = repo.MemoryUserRepository()
    repo.reset_repository(store)
    service.reset_rate_limits()
    yield store
    repo.reset_repository(None)


def register(client, **overrides):
    return client.post("/api/auth/register", json={**VALID, **overrides})


# --- Primitives ---------------------------------------------------------------

def test_le_hash_bcrypt_est_sale():
    """Deux hachages du meme mot de passe different : le sel est bien aleatoire."""
    first = hash_password("meme-mot-de-passe")
    second = hash_password("meme-mot-de-passe")
    assert first != second
    assert verify_password("meme-mot-de-passe", first)
    assert verify_password("meme-mot-de-passe", second)


def test_le_mauvais_mot_de_passe_est_refuse():
    assert not verify_password("mauvais", hash_password("bon-mot-de-passe"))


def test_un_hash_corrompu_refuse_sans_lever():
    """Une valeur illisible en base doit produire un refus, pas une 500."""
    assert not verify_password("quoi-que-ce-soit", "pas-un-hash-bcrypt")


def test_aller_retour_du_jeton():
    token, ttl = create_token("user-1", "alice@example.com")
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["email"] == "alice@example.com"
    assert ttl > 0


def test_un_jeton_altere_est_rejete():
    token, _ = create_token("user-1", "alice@example.com")
    assert decode_token(token[:-2] + "xx") is None
    assert decode_token("nimporte.quoi") is None


# --- Inscription --------------------------------------------------------------

def test_inscription_reussie(client):
    response = register(client)
    assert response.status_code == 201

    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["user"]["first_name"] == "Alice"
    assert body["user"]["country"] == "Niger"


def test_l_email_est_normalise_en_minuscules(client):
    body = register(client).json()
    assert body["user"]["email"] == "alice@example.com"


def test_la_reponse_ne_contient_jamais_le_mot_de_passe(client):
    raw = register(client).text
    assert VALID["password"] not in raw
    assert "password_hash" not in raw


def test_email_deja_pris(client):
    assert register(client).status_code == 201
    # Casse differente : doit quand meme etre reconnu comme doublon.
    duplicate = register(client, email="ALICE@example.com")
    assert duplicate.status_code == 409


@pytest.mark.parametrize(
    "champ,valeur",
    [
        ("email", "pas-un-email"),
        ("password", "court"),          # sous le minimum de 10 caracteres
        ("first_name", "   "),          # vide une fois normalise
        ("country", "N"),               # sous le minimum de 2 caracteres
        ("city", ""),
    ],
)
def test_entrees_invalides_refusees(client, champ, valeur):
    assert register(client, **{champ: valeur}).status_code == 422


def test_mot_de_passe_trop_long_pour_bcrypt(client):
    """Au-dela de 72 octets bcrypt tronque : on refuse plutot que de tronquer."""
    assert register(client, password="a" * 73).status_code == 422


def test_les_espaces_des_champs_texte_sont_normalises(client):
    body = register(client, first_name="  Alice   Marie  ").json()
    assert body["user"]["first_name"] == "Alice Marie"


# --- Connexion ----------------------------------------------------------------

def test_connexion_reussie(client):
    register(client)
    response = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": VALID["password"]},
    )
    assert response.status_code == 200
    assert response.json()["user"]["city"] == "Niamey"


def test_connexion_insensible_a_la_casse_de_l_email(client):
    register(client)
    response = client.post(
        "/api/auth/login",
        json={"email": "ALICE@EXAMPLE.com", "password": VALID["password"]},
    )
    assert response.status_code == 200


def test_mauvais_mot_de_passe_refuse(client):
    register(client)
    response = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "mauvais mot de passe"},
    )
    assert response.status_code == 401


def test_compte_inconnu_et_mauvais_mot_de_passe_donnent_le_meme_message(client):
    """Le message ne doit pas reveler si l'e-mail existe."""
    register(client)
    inconnu = client.post(
        "/api/auth/login",
        json={"email": "bob@example.com", "password": VALID["password"]},
    )
    mauvais = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "mauvais mot de passe"},
    )
    assert inconnu.status_code == mauvais.status_code == 401
    assert inconnu.json()["detail"] == mauvais.json()["detail"]


def test_limitation_du_nombre_de_tentatives(client):
    register(client)
    payload = {"email": "alice@example.com", "password": "mauvais"}

    for _ in range(10):
        assert client.post("/api/auth/login", json=payload).status_code == 401

    assert client.post("/api/auth/login", json=payload).status_code == 429


def test_une_connexion_reussie_remet_le_compteur_a_zero(client):
    register(client)
    for _ in range(5):
        client.post("/api/auth/login", json={"email": VALID["email"], "password": "faux"})

    ok = client.post(
        "/api/auth/login",
        json={"email": VALID["email"], "password": VALID["password"]},
    )
    assert ok.status_code == 200

    for _ in range(10):
        assert (
            client.post(
                "/api/auth/login", json={"email": VALID["email"], "password": "faux"}
            ).status_code
            == 401
        )


# --- Profil -------------------------------------------------------------------

def test_me_renvoie_le_profil(client):
    token = register(client).json()["access_token"]
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"
    assert "password_hash" not in response.json()


@pytest.mark.parametrize(
    "entete",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic abcdef"},
        {"Authorization": "Bearer jeton.invalide.ici"},
    ],
)
def test_me_refuse_sans_jeton_valide(client, entete):
    assert client.get("/api/auth/me", headers=entete).status_code == 401


def test_me_refuse_un_jeton_dont_le_compte_a_disparu(client, memory_store):
    """Jeton correctement signe, mais compte supprime entre-temps."""
    token = register(client).json()["access_token"]
    memory_store.clear()
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# --- Depot --------------------------------------------------------------------

def test_le_depot_memoire_refuse_les_doublons(memory_store):
    document = repo.new_user_document(
        email="a@b.co",
        password_hash="x",
        first_name="A",
        last_name="B",
        country="C",
        city="D",
    )
    memory_store.create(document)
    with pytest.raises(repo.DuplicateEmailError):
        memory_store.create(dict(document, _id="autre-id"))


def test_normalisation_des_emails():
    assert repo.normalise_email("  Alice@Example.COM ") == "alice@example.com"
