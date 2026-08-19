#!/usr/bin/env python3
"""
Test de fumee post-deploiement.

Verifie qu'une instance deployee repond correctement sur ses routes
essentielles, et surtout que les vecteurs de reference y sont toujours justes.
Un deploiement qui casse la crypto doit etre visible immediatement.

Usage :
    python scripts/smoke_test.py https://cryptolab-backend.onrender.com
"""

import json
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 30

# (methode, chemin, corps, cle attendue, valeur attendue)
CHECKS = [
    ("GET", "/health", None, "status", "ok"),
    # Les comptes doivent etre servis par Atlas, pas par le repli memoire : ce
    # dernier ferait disparaitre toutes les inscriptions au premier redemarrage.
    ("GET", "/health", None, "accounts_backend", "mongodb"),
    (
        "POST",
        "/api/classical/caesar/encrypt",
        {"text": "BONJOUR", "shift": 3},
        "cipher",
        "ERQMRXU",
    ),
    (
        "POST",
        "/api/classical/railfence/encrypt",
        {"text": "WEAREDISCOVERED", "shift": 3},
        "cipher",
        "WECRERDSOEEAIVD",
    ),
    (
        "POST",
        "/api/classical/columnar/encrypt",
        {"text": "WEAREDISCOVEREDFLEEATONCE", "key": "ZEBRAS"},
        "cipher",
        "EVLNACDTESEAROFODEECWIREE",
    ),
    (
        "POST",
        "/api/classical/playfair/encrypt",
        {"text": "HIDE THE GOLD IN THE TREE STUMP", "key": "PLAYFAIREXAMPLE"},
        "cipher",
        "BMODZBXDNABEKUDMUIXMMOUVIF",
    ),
    (
        "POST",
        "/api/hash/sha256",
        {"text": "abc"},
        "hash",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        "POST",
        "/api/simulate/aes",
        {"text": "Two One Nine Two", "key": "Thats my Kung Fu"},
        "final_result_hex",
        "29c3505f571420f6402299b31a02d73a",
    ),
]


def call(base_url: str, method: str, path: str, body: dict | None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read())


def wait_until_awake(base_url: str, attempts: int = 20, delay: int = 15) -> None:
    """
    Le plan gratuit de Render met l'instance en veille : le premier appel peut
    prendre presque une minute. On attend avant de conclure a une panne.
    """
    for attempt in range(1, attempts + 1):
        try:
            call(base_url, "GET", "/health", None)
            print(f"Instance reveillee (tentative {attempt}).")
            return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"  tentative {attempt}/{attempts} : pas encore prete ({exc})")
            time.sleep(delay)

    print("ECHEC : l'instance n'a jamais repondu.", file=sys.stderr)
    sys.exit(1)


def check_auth_is_closed(base_url: str) -> bool:
    """
    Une requete anonyme sur /api/auth/me doit etre refusee.

    C'est la verification qui compte le plus apres un deploiement : si elle
    passait, le cours et le laboratoire seraient ouverts a tous.
    """
    try:
        call(base_url, "GET", "/api/auth/me", None)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            print("  OK     GET /api/auth/me refuse l'acces anonyme")
            return True
        print(f"  ECHEC  GET /api/auth/me repond {exc.code}, attendu 401")
        return False
    except Exception as exc:
        print(f"  ECHEC  GET /api/auth/me -> {exc}")
        return False

    print("  ECHEC  GET /api/auth/me repond 200 sans jeton : l'API est ouverte.")
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    base_url = sys.argv[1]
    print(f"Test de fumee sur {base_url}\n")
    wait_until_awake(base_url)

    failures = 0
    for method, path, body, key, expected in CHECKS:
        label = f"{method} {path}"
        try:
            result = call(base_url, method, path, body)
        except Exception as exc:
            print(f"  ECHEC  {label} -> {exc}")
            failures += 1
            continue

        actual = result.get(key)
        if actual == expected:
            print(f"  OK     {label}")
        else:
            print(f"  ECHEC  {label}\n         attendu : {expected}\n         recu    : {actual}")
            failures += 1

    if not check_auth_is_closed(base_url):
        failures += 1

    print()
    if failures:
        print(f"{failures} verification(s) en echec.", file=sys.stderr)
        return 1

    print(f"Les {len(CHECKS) + 1} verifications passent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
