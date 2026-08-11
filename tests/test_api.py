"""
Tests de l'API HTTP : contrat des routes, validation des entrees, et surtout
la garantie qu'aucune donnee utilisateur n'est persistee.
"""

import pytest

# --- Meta --------------------------------------------------------------------

def test_root_is_alive(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["educational_only"] is True


def test_health_reports_stats_disabled_by_default(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["anonymous_stats"] is False


# --- Confidentialite ---------------------------------------------------------

def test_no_user_data_is_ever_persisted(client, monkeypatch):
    """
    Regression majeure : chaque route enregistrait le texte clair de
    l'utilisateur dans MongoDB, y compris pour RSA et AES.

    On intercepte desormais l'enregistrement et on verifie qu'il ne recoit
    que des metadonnees : nom d'algorithme, action, et longueur.
    """
    captured = []

    from db import crud

    def spy(algorithm, action, input_length=0):
        captured.append((algorithm, action, input_length))

    monkeypatch.setattr(crud, "record_usage", spy)
    # Les routeurs importent `crud` comme module, la substitution les couvre tous.

    secret = "MON-SECRET-ABSOLU"
    client.post("/api/classical/caesar/encrypt", json={"text": secret, "shift": 3})
    client.post("/api/hash/sha256", json={"text": secret})
    client.post("/api/modern/aes/encrypt", json={"text": secret, "key": "cle"})

    assert captured == [
        ("caesar", "encrypt", len(secret)),
        ("sha256", "hash", len(secret)),
        ("aes-gcm", "encrypt", len(secret)),
    ]
    # Aucun element capture ne doit contenir le secret lui-meme.
    assert all(secret not in str(item) for item in captured)


def test_usage_event_rejects_nothing_but_metadata():
    """Le modele de statistiques n'a aucun champ pouvant porter du contenu."""
    from db.models import UsageEvent

    fields = set(UsageEvent.model_fields)
    assert fields == {"algorithm", "action", "input_length", "timestamp"}


def test_usage_event_timestamp_is_not_frozen():
    """
    Regression : `timestamp: datetime = datetime.now()` etait evalue une seule
    fois a l'import, si bien que tous les evenements portaient l'heure de
    demarrage du serveur.
    """
    import time

    from db.models import UsageEvent

    first = UsageEvent(algorithm="a", action="b")
    time.sleep(0.01)
    second = UsageEvent(algorithm="a", action="b")
    assert first.timestamp != second.timestamp


# --- Chiffres classiques -----------------------------------------------------

def test_caesar_endpoint(client):
    body = client.post("/api/classical/caesar/encrypt", json={"text": "BONJOUR", "shift": 3}).json()
    assert body["cipher"] == "ERQMRXU"


def test_railfence_endpoint_is_a_real_zigzag(client):
    """Regression : cette route servait une transposition par colonnes."""
    body = client.post(
        "/api/classical/railfence/encrypt", json={"text": "WEAREDISCOVERED", "shift": 3}
    ).json()
    assert body["cipher"] == "WECRERDSOEEAIVD"


def test_columnar_endpoint(client):
    body = client.post(
        "/api/classical/columnar/encrypt",
        json={"text": "WEAREDISCOVEREDFLEEATONCE", "key": "ZEBRAS"},
    ).json()
    assert body["cipher"] == "EVLNACDTESEAROFODEECWIREE"
    assert body["key_order"] == [4, 2, 1, 3, 5, 0]


def test_playfair_decrypt_strips_padding(client):
    body = client.post(
        "/api/classical/playfair/decrypt", json={"text": "CFSUPMVNMTBZ", "key": "MONARCHY"}
    ).json()
    assert body["plain"] == "HELLOWORLD"
    assert body["plain_raw"] == "HELXLOWORLDX"


@pytest.mark.parametrize(
    "endpoint, payload",
    [
        ("/api/classical/caesar/encrypt", {"text": "ABC", "shift": 5}),
        ("/api/classical/vigenere/encrypt", {"text": "ABC", "key": "KEY"}),
        ("/api/classical/playfair/encrypt", {"text": "ABC", "key": "KEY"}),
        ("/api/classical/railfence/encrypt", {"text": "ABC", "shift": 2}),
        ("/api/classical/columnar/encrypt", {"text": "ABC", "key": "KEY"}),
    ],
)
def test_classical_endpoints_round_trip(client, endpoint, payload):
    cipher = client.post(endpoint, json=payload).json()["cipher"]
    decrypt_payload = {**payload, "text": cipher}
    plain = client.post(endpoint.replace("encrypt", "decrypt"), json=decrypt_payload).json()["plain"]
    assert plain == payload["text"]


# --- Validation des entrees --------------------------------------------------

@pytest.mark.parametrize(
    "endpoint, payload",
    [
        ("/api/classical/caesar/encrypt", {"text": "ABC"}),                 # shift manquant
        ("/api/classical/caesar/encrypt", {"text": "ABC", "shift": "x"}),   # shift non entier
        ("/api/classical/vigenere/encrypt", {"text": "ABC", "key": ""}),    # cle vide
        ("/api/classical/caesar/encrypt", {"text": "A" * 20_001, "shift": 3}),  # trop long
        ("/api/hash/sha256", {}),                                           # texte manquant
    ],
)
def test_invalid_input_returns_422(client, endpoint, payload):
    assert client.post(endpoint, json=payload).status_code == 422


# --- Hachage -----------------------------------------------------------------

def test_sha256_endpoint(client):
    body = client.post("/api/hash/sha256", json={"text": "abc"}).json()
    assert body["hash"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_bcrypt_endpoints(client):
    hashed = client.post("/api/hash/bcrypt", json={"text": "motdepasse"}).json()["hash"]
    verified = client.post(
        "/api/hash/bcrypt/verify", json={"text": "motdepasse", "hashed_text": hashed}
    ).json()
    assert verified["match"] is True


# --- Symetrique moderne ------------------------------------------------------

def test_aes_endpoints_round_trip(client):
    encrypted = client.post(
        "/api/modern/aes/encrypt", json={"text": "Message secret", "key": "ma-cle"}
    ).json()
    decrypted = client.post(
        "/api/modern/aes/decrypt",
        json={
            "cipher_hex": encrypted["cipher_hex"],
            "key": "ma-cle",
            "nonce_hex": encrypted["nonce_hex"],
            "tag_hex": encrypted["tag_hex"],
        },
    ).json()
    assert decrypted["success"] is True
    assert decrypted["plain"] == "Message secret"


def test_des_endpoints_round_trip(client):
    encrypted = client.post(
        "/api/modern/des/encrypt", json={"text": "Message secret", "key": "ma-cle"}
    ).json()
    decrypted = client.post(
        "/api/modern/des/decrypt",
        json={
            "cipher_hex": encrypted["cipher_hex"],
            "key": "ma-cle",
            "iv_hex": encrypted["iv_hex"],
        },
    ).json()
    assert decrypted["success"] is True
    assert decrypted["plain"] == "Message secret"


# --- RSA ---------------------------------------------------------------------

def test_rsa_endpoints_round_trip(client):
    keys = client.get("/api/asymmetric/rsa/generate-keys").json()
    encrypted = client.post(
        "/api/asymmetric/rsa/encrypt",
        json={"text": "Message secret", "public_key": keys["public_key"]},
    ).json()
    assert encrypted["success"] is True

    decrypted = client.post(
        "/api/asymmetric/rsa/decrypt",
        json={"cipher_hex": encrypted["cipher_hex"], "private_key": keys["private_key"]},
    ).json()
    assert decrypted["success"] is True
    assert decrypted["plain"] == "Message secret"


# --- Simulations -------------------------------------------------------------

def test_simulate_lists_available_algorithms(client):
    algorithms = client.get("/api/simulate").json()["algorithms"]
    assert algorithms == ["aes", "caesar", "columnar", "des", "playfair", "railfence", "vigenere"]


@pytest.mark.parametrize(
    "algo, payload",
    [
        ("caesar", {"text": "BONJOUR", "shift": 3}),
        ("vigenere", {"text": "ATTACKATDAWN", "key": "LEMON"}),
        ("playfair", {"text": "HELLO WORLD", "key": "MONARCHY"}),
        ("railfence", {"text": "WEAREDISCOVERED", "shift": 3}),
        ("columnar", {"text": "WEAREDISCOVERED", "key": "ZEBRAS"}),
        ("des", {"text": "12345678", "key": "abcdefgh"}),
        ("aes", {"text": "Two One Nine Two", "key": "Thats my Kung Fu"}),
    ],
)
def test_simulations_return_described_steps(client, algo, payload):
    body = client.post(f"/api/simulate/{algo}", json=payload).json()
    assert body["algorithm"] == algo
    assert len(body["steps"]) > 1
    assert all(step.get("description") for step in body["steps"])
    assert body.get("final_result") or body.get("final_result_hex")


def test_unknown_simulation_returns_404(client):
    response = client.post("/api/simulate/enigma", json={"text": "A", "key": "B"})
    assert response.status_code == 404
    assert "enigma" in response.json()["detail"]


def test_simulation_with_bad_input_returns_422(client):
    assert client.post("/api/simulate/caesar", json={"text": "ABC"}).status_code == 422


def test_simulation_never_leaks_internal_errors(client, monkeypatch):
    """Une exception interne ne doit pas remonter sa trace au client."""
    from routers import simulate as simulate_router

    def boom(*_args, **_kwargs):
        raise RuntimeError("chemin/interne/secret.py ligne 42")

    model, _, extract = simulate_router.SIMULATORS["caesar"]
    monkeypatch.setitem(simulate_router.SIMULATORS, "caesar", (model, boom, extract))

    response = client.post("/api/simulate/caesar", json={"text": "ABC", "shift": 3})
    assert response.status_code == 500
    assert "secret.py" not in response.json()["detail"]
