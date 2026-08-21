"""
Tests du registre d'algorithmes.

Le test central est `test_official_vector` : il rejoue *tous* les vecteurs
declares par *tous* les algorithmes, a travers l'API reelle. Ajouter un
algorithme sans vecteur echoue au test de completude ; declarer un vecteur faux
echoue ici. C'est ce qui autorise le site a afficher « valide contre n vecteurs
officiels ».
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from registry import registry
from registry.spec import Family

client = TestClient(app)


def unwrap(response) -> dict:
    """Verifie l'enveloppe et retourne `data`."""
    body = response.json()
    assert set(body) == {"ok", "data", "error"}, body
    assert body["ok"] is True, body
    assert body["error"] is None
    return body["data"]


def error_of(response) -> dict:
    body = response.json()
    assert set(body) == {"ok", "data", "error"}, body
    assert body["ok"] is False, body
    assert body["data"] is None
    return body["error"]


# --- Vecteurs officiels ------------------------------------------------------

VECTORS = registry.vectors()


@pytest.mark.parametrize(
    ("algorithm", "vector"),
    VECTORS,
    ids=[f"{a.slug}-{v.operation}-{i}" for i, (a, v) in enumerate(VECTORS)],
)
def test_official_vector(algorithm, vector):
    """Chaque vecteur declare doit passer a travers l'API publique."""
    operation = algorithm.operation(vector.operation)
    assert operation is not None, (
        f"{algorithm.slug} declare un vecteur pour '{vector.operation}', "
        f"operation qui n'existe pas."
    )

    url = f"{algorithm.family.prefix}{operation.resolved_path(algorithm.slug)}"
    response = client.request(operation.method, url, json=vector.inputs)

    assert response.status_code == 200, response.text
    data = unwrap(response)

    for field, expected in vector.expected.items():
        assert data[field] == expected, (
            f"{algorithm.slug}.{vector.operation} : champ '{field}'\n"
            f"  attendu : {expected!r}\n"
            f"  obtenu  : {data[field]!r}\n"
            f"  source  : {vector.source}"
        )


def test_every_deterministic_algorithm_has_a_vector():
    """
    Tout algorithme deterministe doit porter au moins un vecteur.

    Les exceptions sont explicites et justifiees : AES-GCM tire un nonce
    aleatoire, DES-CBC un IV, RSA-OAEP un remplissage. Leur sortie change a
    chaque appel, aucun vecteur fixe n'est possible sur ces routes — leur
    correction est prouvee ailleurs (aller-retour, et vecteurs FIPS sur les
    simulateurs pas a pas, qui sont deterministes).
    """
    PROBABILISTIC = {"aes", "des", "rsa"}

    missing = [
        algo.slug
        for algo in registry.all()
        if not algo.vectors and algo.slug not in PROBABILISTIC
    ]
    assert missing == [], f"Algorithmes sans vecteur de test : {missing}"


# --- Structure du registre ---------------------------------------------------

def test_registry_holds_every_algorithm():
    # Sprint 4 : +7 (MD5, SHA-1, SHA-3-256, BLAKE2b, HMAC-SHA256, PBKDF2, scrypt).
    assert len(registry) == 17
    assert {a.slug for a in registry.all()} == {
        "caesar", "vigenere", "playfair", "railfence", "columnar",
        "aes", "des", "rsa", "sha256", "bcrypt",
        "md5", "sha1", "sha3256", "blake2b", "hmacsha256", "pbkdf2", "scrypt",
    }


def test_slugs_are_url_safe():
    for algorithm in registry.all():
        assert algorithm.slug.islower()
        assert algorithm.slug.isalnum(), f"{algorithm.slug} n'est pas alphanumerique"


def test_operations_are_unique_per_algorithm():
    for algorithm in registry.all():
        names = [op.name for op in algorithm.operations]
        assert len(names) == len(set(names)), f"{algorithm.slug} : operations en double"


def test_generated_paths_are_unique():
    """Deux algorithmes ne peuvent pas revendiquer la meme URL."""
    seen: dict[tuple[str, str], str] = {}
    for algorithm in registry.all():
        for operation in algorithm.operations:
            key = (operation.method, f"{algorithm.family.prefix}{operation.resolved_path(algorithm.slug)}")
            assert key not in seen, f"{key} revendique par {seen.get(key)} et {algorithm.slug}"
            seen[key] = algorithm.slug


#: Les 20 URL publiques de la v1, telles que le frontend les appelle.
PUBLIC_V1_URLS = [
    ("POST", "/api/classical/caesar/encrypt"),
    ("POST", "/api/classical/caesar/decrypt"),
    ("POST", "/api/classical/vigenere/encrypt"),
    ("POST", "/api/classical/vigenere/decrypt"),
    ("POST", "/api/classical/playfair/encrypt"),
    ("POST", "/api/classical/playfair/decrypt"),
    ("POST", "/api/classical/railfence/encrypt"),
    ("POST", "/api/classical/railfence/decrypt"),
    ("POST", "/api/classical/columnar/encrypt"),
    ("POST", "/api/classical/columnar/decrypt"),
    ("POST", "/api/modern/aes/encrypt"),
    ("POST", "/api/modern/aes/decrypt"),
    ("POST", "/api/modern/des/encrypt"),
    ("POST", "/api/modern/des/decrypt"),
    ("GET", "/api/asymmetric/rsa/generate-keys"),
    ("POST", "/api/asymmetric/rsa/encrypt"),
    ("POST", "/api/asymmetric/rsa/decrypt"),
    ("POST", "/api/hash/sha256"),
    ("POST", "/api/hash/bcrypt"),
    ("POST", "/api/hash/bcrypt/verify"),
]


@pytest.mark.parametrize(("method", "url"), PUBLIC_V1_URLS, ids=[u for _, u in PUBLIC_V1_URLS])
def test_public_url_still_answers(method, url):
    """
    Chaque URL de la v1 doit toujours repondre.

    Le registre a remplace les routeurs ecrits a la main ; si une URL bougeait,
    les pages en ligne tomberaient sans que rien d'autre ne le signale.

    On appelle reellement la route plutot que d'introspecter `app.routes` : ce
    qui compte est le contrat servi, pas la structure interne de FastAPI. Un
    corps vide suffit — une route qui existe repond 422 (validation), une route
    disparue repond 404.
    """
    response = client.request(method, url, json={})

    assert response.status_code != 404, f"{method} {url} a disparu."


def test_openapi_publishes_every_public_url():
    """La documentation publiee doit decrire les memes routes."""
    paths = client.get("/openapi.json").json()["paths"]

    for method, url in PUBLIC_V1_URLS:
        assert url in paths, f"{url} absente de l'OpenAPI."
        assert method.lower() in paths[url], f"{method} {url} absente de l'OpenAPI."


# --- Catalogue public --------------------------------------------------------

def test_catalog_lists_every_algorithm():
    data = unwrap(client.get("/api/algorithms"))

    assert data["count"] == len(registry)
    assert data["total_vectors"] == sum(len(a.vectors) for a in registry.all())
    assert {f["value"] for f in data["families"]} == {f.value for f in Family}

    caesar = next(a for a in data["algorithms"] if a["slug"] == "caesar")
    assert caesar["maturity"] == "broken"
    assert caesar["simulator"] == "caesar"
    assert caesar["vector_count"] == 3
    # Le schema d'entree accompagne chaque operation : le frontend peut
    # construire son formulaire sans rien coder en dur.
    encrypt = next(op for op in caesar["operations"] if op["name"] == "encrypt")
    assert encrypt["path"] == "/api/classical/caesar/encrypt"
    assert "shift" in encrypt["schema"]["properties"]


def test_catalog_filters_by_family():
    data = unwrap(client.get("/api/algorithms", params={"family": "classical"}))

    assert data["count"] == 5
    assert {a["family"] for a in data["algorithms"]} == {"classical"}


def test_catalog_search_matches_name_summary_and_aliases():
    by_alias = unwrap(client.get("/api/algorithms", params={"q": "feistel"}))
    assert [a["slug"] for a in by_alias["algorithms"]] == ["des"]

    by_name = unwrap(client.get("/api/algorithms", params={"q": "cesar"}))
    assert "caesar" in [a["slug"] for a in by_name["algorithms"]]


def test_catalog_detail_exposes_the_vectors():
    data = unwrap(client.get("/api/algorithms/sha256"))

    assert data["name"] == "SHA-256"
    assert len(data["vectors"]) == 3
    assert all("FIPS 180-4" in v["source"] for v in data["vectors"])


def test_catalog_detail_rejects_an_unknown_slug():
    response = client.get("/api/algorithms/enigma")

    assert response.status_code == 404
    error = error_of(response)
    assert error["code"] == "unknown_algorithm"
    # L'erreur est utile : elle dit ce qui existe.
    assert "caesar" in error["details"]["available"]


# --- Enveloppe et codes HTTP -------------------------------------------------

def test_success_is_wrapped():
    data = unwrap(client.post("/api/classical/caesar/encrypt", json={"text": "abc", "shift": 1}))

    assert data == {"algorithm": "caesar", "action": "encrypt", "cipher": "bcd"}


def test_validation_error_is_422_and_wrapped():
    response = client.post("/api/classical/caesar/encrypt", json={"text": "abc"})

    assert response.status_code == 422
    error = error_of(response)
    assert error["code"] == "validation_error"
    assert "shift" in error["message"]
    assert error["details"]["errors"]


def test_decryption_failure_is_400_not_200():
    """
    Le coeur du sprint : un echec de dechiffrement etait renvoye en 200 OK avec
    la chaine « Erreur: ... » dans le champ resultat. Un texte contenant ce mot
    cassait le contrat, et aucun client HTTP ne pouvait detecter l'echec.
    """
    encrypted = unwrap(
        client.post("/api/modern/aes/encrypt", json={"text": "secret", "key": "bonne-cle"})
    )

    response = client.post(
        "/api/modern/aes/decrypt",
        json={
            "cipher_hex": encrypted["cipher_hex"],
            "key": "mauvaise-cle",
            "nonce_hex": encrypted["nonce_hex"],
            "tag_hex": encrypted["tag_hex"],
            "salt_hex": encrypted["salt_hex"],
        },
    )

    assert response.status_code == 400
    error = error_of(response)
    assert error["code"] == "decryption_failed"
    assert "tag" in error["message"]


def test_aes_round_trip_through_the_envelope():
    encrypted = unwrap(
        client.post("/api/modern/aes/encrypt", json={"text": "Bonjour Monastir", "key": "cle"})
    )
    decrypted = unwrap(
        client.post(
            "/api/modern/aes/decrypt",
            json={
                "cipher_hex": encrypted["cipher_hex"],
                "key": "cle",
                "nonce_hex": encrypted["nonce_hex"],
                "tag_hex": encrypted["tag_hex"],
                "salt_hex": encrypted["salt_hex"],
            },
        )
    )

    assert decrypted["plain"] == "Bonjour Monastir"


def test_des_round_trip_through_the_envelope():
    encrypted = unwrap(
        client.post("/api/modern/des/encrypt", json={"text": "Feistel", "key": "cle"})
    )
    decrypted = unwrap(
        client.post(
            "/api/modern/des/decrypt",
            json={
                "cipher_hex": encrypted["cipher_hex"],
                "key": "cle",
                "iv_hex": encrypted["iv_hex"],
                "salt_hex": encrypted["salt_hex"],
            },
        )
    )

    assert decrypted["plain"] == "Feistel"


def test_bad_hex_is_reported_as_invalid_input():
    response = client.post(
        "/api/modern/des/decrypt",
        json={
            "cipher_hex": "pas-du-hex", "key": "cle", "iv_hex": "00" * 8, "salt_hex": "00" * 16,
        },
    )

    assert response.status_code == 400
    assert error_of(response)["code"] == "invalid_input"


def test_rsa_round_trip_and_typed_errors():
    keys = unwrap(client.get("/api/asymmetric/rsa/generate-keys"))

    encrypted = unwrap(
        client.post(
            "/api/asymmetric/rsa/encrypt",
            json={"text": "cle de session", "public_key": keys["public_key"]},
        )
    )
    decrypted = unwrap(
        client.post(
            "/api/asymmetric/rsa/decrypt",
            json={"cipher_hex": encrypted["cipher_hex"], "private_key": keys["private_key"]},
        )
    )
    assert decrypted["plain"] == "cle de session"

    # Une clef illisible n'est pas la meme erreur qu'un message trop long :
    # l'ancienne version les confondait dans une seule chaine.
    bad_key = client.post(
        "/api/asymmetric/rsa/encrypt",
        json={"text": "coucou", "public_key": "pas-une-cle"},
    )
    assert bad_key.status_code == 400
    assert error_of(bad_key)["code"] == "invalid_key"


def test_auth_keeps_the_fastapi_error_contract():
    """
    L'authentification reste hors enveloppe, et c'est deliberе.

    Ses reponses sont relayees par les route handlers Next, qui lisent `detail`
    pour en tirer le message affiche a l'etudiant. Ce chemin est couvert par les
    tests du frontend ; l'envelopper changerait un contrat de securite sans rien
    corriger — ces routes emettaient deja de vrais codes HTTP.
    """
    response = client.post("/api/auth/login", json={"email": "x", "password": "y"})

    assert response.status_code == 422
    assert "detail" in response.json()
    assert "ok" not in response.json()


def test_internal_error_does_not_leak_the_traceback(monkeypatch):
    """Une panne inattendue ne doit jamais exposer l'interne au client."""
    def boom(*_args, **_kwargs):
        raise RuntimeError("chemin/interne/secret.py ligne 42")

    monkeypatch.setattr("utils.caesar.caesar_encrypt", boom)

    response = client.post("/api/classical/caesar/encrypt", json={"text": "abc", "shift": 1})

    assert response.status_code == 500
    error = error_of(response)
    assert "secret.py" not in error["message"]
    assert error["code"] == "internal_error"
