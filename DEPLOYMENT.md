# Déploiement — backend CryptoLab

## Le principe

Rien ne part en production sans être passé au vert.

```
push sur master
   │
   ├─► CI ──── ruff + 199 tests sur Python 3.10 → 3.13
   │           + vérification qu'aucun .env ni .idea/ n'est commité
   │
   └─► si et seulement si la CI est verte :
         Deploy ──► hook Render ──► attente ──► test de fumée sur /health
                                                et sur 7 vecteurs de référence
```

Le test de fumée rejoue les vecteurs canoniques **sur l'instance déployée**.
Un déploiement qui casserait AES, Playfair ou SHA-256 est détecté en une minute.

## Mise en place, une seule fois

### 1. Couper l'auto-déploiement de Render

Sans cela, Render déploie dès le push, sans attendre la CI — c'est exactement
ce qu'on cherche à éviter.

> Dashboard Render → votre service → **Settings** → **Auto-Deploy** → `Off`

### 2. Récupérer le Deploy Hook

> Dashboard Render → votre service → **Settings** → **Deploy Hook** → copier l'URL

### 3. L'enregistrer comme secret GitHub

> GitHub → dépôt → **Settings** → **Secrets and variables** → **Actions** →
> **New repository secret**

| Nom | Valeur |
|---|---|
| `RENDER_DEPLOY_HOOK_URL` | l'URL copiée à l'étape 2 |

Et, dans l'onglet **Variables** (facultatif, si votre URL diffère) :

| Nom | Valeur |
|---|---|
| `API_URL` | `https://cryptolab-api.onrender.com` |

### 4. Variables d'environnement côté Render

> Dashboard Render → votre service → **Environment**

| Clé | Valeur | Note |
|---|---|---|
| `PYTHON_VERSION` | `3.12` | |
| `CRYPTOLAB_ENABLE_STATS` | `false` | aucune donnée utilisateur enregistrée |
| `CRYPTOLAB_ALLOWED_ORIGINS` | `https://cryptolaboratory.vercel.app` | origines CORS, séparées par des virgules |
| `MONGO_URI` | *(optionnel)* | requis seulement si les stats sont activées |

> **À faire maintenant** : l'ancienne URI Mongo a vécu dans un dépôt sans
> `.gitignore`. Considérez-la comme exposée et **faites-la tourner** dans
> MongoDB Atlas avant toute remise en service.

## Déclencher un déploiement à la main

> GitHub → **Actions** → **Deploy** → **Run workflow**

## Vérifier une instance sans passer par la CI

```bash
python scripts/smoke_test.py https://cryptolab-api.onrender.com
```

Le script patiente pendant le réveil de l'instance : sur le plan gratuit de
Render, le premier appel après une période d'inactivité peut prendre une minute.

## Fichiers concernés

| Fichier | Rôle |
|---|---|
| `.github/workflows/ci.yml` | lint, tests, garde-fous sur les secrets |
| `.github/workflows/deploy.yml` | déploiement déclenché par une CI verte |
| `render.yaml` | infrastructure Render en tant que code |
| `scripts/smoke_test.py` | vérification post-déploiement |
