"""
Generation des routes a partir du registre.

Les routes ne sont plus ecrites a la main : elles sont derivees de la
declaration de chaque algorithme. Les URL publiques sont identiques a celles de
la v1 — `/api/classical/caesar/encrypt`, `/api/hash/sha256`,
`/api/asymmetric/rsa/generate-keys` — parce que les casser ferait tomber les
pages en ligne. Seule l'enveloppe de reponse change.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

from fastapi import APIRouter

from db import crud
from registry.envelope import success
from registry.errors import CryptoLabError
from registry.spec import Algorithm, Family, Operation, Registry

logger = logging.getLogger(__name__)


def _run(algorithm: Algorithm, operation: Operation, payload: Any) -> Any:
    """Execute une operation et l'emballe dans l'enveloppe."""
    try:
        data = operation.handler(payload)
    except CryptoLabError:
        # Erreur metier : le gestionnaire global la traduit en enveloppe.
        raise
    except Exception as exc:
        # Panne inattendue : on garde la trace cote serveur et on n'expose rien
        # de l'interne au client.
        logger.exception(
            "Echec de %s/%s", algorithm.slug, operation.name
        )
        raise CryptoLabError(
            f"Erreur interne pendant l'operation '{operation.name}' de "
            f"'{algorithm.slug}'."
        ) from exc

    length = 0
    if payload is not None:
        length = len(str(getattr(payload, operation.length_field, "") or ""))
    crud.record_usage(algorithm.slug, operation.name, length)

    return success({"algorithm": algorithm.slug, "action": operation.name, **data})


def _add_route(router: APIRouter, algorithm: Algorithm, operation: Operation) -> None:
    """Declare une route FastAPI pour une operation."""
    path = operation.resolved_path(algorithm.slug)
    doc = operation.description or operation.summary

    if operation.input_model is None:
        # Operation sans corps de requete (RSA generate-keys).
        def endpoint() -> Any:  # noqa: ANN202 - signature imposee par FastAPI
            return _run(algorithm, operation, None)
    else:
        model = operation.input_model

        def endpoint(payload) -> Any:  # noqa: ANN001, ANN202
            return _run(algorithm, operation, payload)

        # FastAPI deduit l'emplacement d'un parametre de son annotation : un
        # modele Pydantic annote devient le corps JSON de la requete, valide et
        # publie dans OpenAPI. Le modele n'etant connu qu'a l'execution, on pose
        # la signature nous-memes plutot que de l'ecrire en dur.
        endpoint.__signature__ = inspect.Signature(
            [
                inspect.Parameter(
                    "payload",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=model,
                )
            ]
        )
        endpoint.__annotations__ = {"payload": model, "return": Any}

    router.add_api_route(
        path,
        endpoint,
        methods=[operation.method],
        summary=f"{algorithm.name} — {operation.summary}",
        description=doc,
        tags=[algorithm.family.label],
        name=f"{algorithm.slug}_{operation.name}",
    )


def build_routers(registry: Registry) -> list[APIRouter]:
    """Un routeur par famille, prefixe par l'URL publique historique."""
    routers: list[APIRouter] = []

    for family in Family:
        algorithms = [algo for algo in registry.all() if algo.family is family]
        if not algorithms:
            continue

        router = APIRouter(prefix=family.prefix, tags=[family.label])
        for algorithm in algorithms:
            for operation in algorithm.operations:
                _add_route(router, algorithm, operation)
        routers.append(router)

    return routers


def build_catalog_router(registry: Registry) -> APIRouter:
    """
    `/api/algorithms` : le catalogue, servi par l'API.

    Le frontend decouvre ainsi ce que le backend sait faire, au lieu de le coder
    en dur. Un algorithme ajoute au registre apparait sur le site sans qu'une
    seule ligne de TypeScript ne change.
    """
    router = APIRouter(prefix="/api/algorithms", tags=["Catalogue"])

    @router.get("", summary="Lister tous les algorithmes exposes")
    def list_algorithms(family: str | None = None, q: str | None = None) -> Any:
        algorithms = registry.all()

        if family:
            algorithms = [a for a in algorithms if a.family.value == family]

        if q:
            needle = q.casefold()
            algorithms = [
                a
                for a in algorithms
                if needle in a.slug
                or needle in a.name.casefold()
                or needle in a.summary.casefold()
                or any(needle in alias for alias in a.aliases)
            ]

        return success(
            {
                "count": len(algorithms),
                "total_vectors": sum(len(a.vectors) for a in algorithms),
                "families": [
                    {"value": f.value, "label": f.label, "prefix": f.prefix} for f in Family
                ],
                "algorithms": [a.describe() for a in algorithms],
            }
        )

    @router.get("/{slug}", summary="Fiche detaillee d'un algorithme")
    def get_algorithm(slug: str) -> Any:
        from registry.errors import UnknownAlgorithm

        algorithm = registry.get(slug)
        if algorithm is None:
            raise UnknownAlgorithm(
                f"Aucun algorithme nomme '{slug}'.",
                details={"available": [a.slug for a in registry.all()]},
            )

        fiche = algorithm.describe()
        # La fiche detaillee expose les vecteurs eux-memes : c'est la preuve
        # publique annoncee par le compteur de la liste.
        fiche["vectors"] = [
            {
                "operation": vector.operation,
                "inputs": vector.inputs,
                "expected": vector.expected,
                "source": vector.source,
            }
            for vector in algorithm.vectors
        ]
        return success(fiche)

    return router
