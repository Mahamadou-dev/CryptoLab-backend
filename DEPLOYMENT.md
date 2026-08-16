# Déploiement — backend CryptoLab

## Où vivent les données

**Il n'y a rien à installer sur Render.** Render ne propose pas de MongoDB
managé — son catalogue de bases couvre PostgreSQL et Key Value/Redis, pas Mongo.
La base reste donc **MongoDB Atlas**, telle qu'elle est déjà, et Render s'y
connecte par `MONGO_URI`. Le service Render n'héberge que l'API Python.

```
Render (web service)  ──MONGO_URI──►  MongoDB Atlas
   uvicorn main:app                     base cryptolab_auth  (comptes)
```

## Le principe

Rien ne part en production sans être passé au vert.

```
push sur master
   │
   ├─► CI ──── ruff + 267 tests sur Python 3.10 → 3.13
   │           + 15 vecteurs officiels
   │           + vérification qu'aucun .env ni .idea/ n'est commité
   │
   └─► si et seulement si la CI est verte :
         Deploy ──► hook Render ──► attente ──► test de fumée sur /health
                                                et sur les vecteurs de référence
```

Le test de fumée rejoue les vecteurs canoniques **sur l'instance déployée**.
Un déploiement qui casserait AES, Playfair ou SHA-256 est détecté en une minute.

> Si le secret `RENDER_DEPLOY_HOOK_URL` n'est pas défini, le workflow `Deploy`
> ne tombe pas en échec : il s'ignore et explique pourquoi dans son résumé. Un
> dépôt qui déploie par l'auto-deploy de Render n'a rien à configurer ici.

## Deux façons de déployer — choisir

| | Auto-Deploy Render `On` | Deploy piloté par la CI |
|---|---|---|
| Mise en place | rien à faire | un secret GitHub |
| Déclencheur | chaque push | une CI verte, et elle seule |
| Un build rouge peut-il partir en prod ? | **oui** | non |
| Test de fumée après déploiement | non | oui |
| Workflow `Deploy` | s'ignore | actif |

**Pour une première mise en ligne, `Auto-Deploy On` est le chemin le plus
court** : aucun secret, le service démarre dès le push. On passe au
déploiement piloté par la CI quand le site a des utilisateurs et qu'une
régression coûte quelque chose.

**Ne pas activer les deux.** Auto-Deploy `On` *et* le hook configuré
déclencheraient deux déploiements concurrents pour un même commit.

## Mise en place — variables d'environnement

> Dashboard Render → votre service → **Environment**

Le fichier `render.yaml` déclare déjà tout ce qui n'est pas secret. Ne restent à
saisir à la main que les deux valeurs marquées `sync: false` :

| Clé | Valeur | Obligatoire |
|---|---|---|
| `CRYPTOLAB_JWT_SECRET` | `python -c "import secrets; print(secrets.token_urlsafe(64))"` | **oui** — l'API refuse de démarrer sans, en production |
| `MONGO_URI` | l'URI Atlas, avec le mot de passe | **oui** — elle porte la base des comptes |

Les autres viennent du Blueprint : `PYTHON_VERSION=3.12`,
`CRYPTOLAB_ENV=production`, `CRYPTOLAB_AUTH_DB=cryptolab_auth`,
`CRYPTOLAB_ENABLE_STATS=false`, `CRYPTOLAB_ALLOWED_ORIGINS`.

> **`MONGO_URI` est requis en production.** Une version antérieure de ce
> document le disait facultatif : c'était vrai quand Mongo ne servait qu'aux
> statistiques, et faux depuis que la base porte les comptes utilisateurs. Sans
> lui, `CRYPTOLAB_ENV=production` fait échouer le démarrage — délibérément :
> mieux vaut un refus net que des inscriptions écrites en mémoire et perdues au
> premier redémarrage.

### Côté MongoDB Atlas

1. **Faire tourner le mot de passe** : l'ancienne URI a vécu dans un dépôt sans
   `.gitignore`. Considérez-la comme exposée.
2. Créer un utilisateur dédié, avec accès à la seule base `cryptolab_auth`.
3. **Network Access** → autoriser `0.0.0.0/0`. Les adresses sortantes de Render
   ne sont pas fixes sur le plan gratuit ; sans cette règle, la connexion échoue
   à l'exécution alors que tout paraît correct.

### Vérifier que la base est bien branchée

```bash
curl https://<votre-service>.onrender.com/health
```

`accounts_backend` doit valoir `"mongodb"`. S'il vaut `"memory"`, les
inscriptions disparaîtront au prochain redémarrage — la connexion Atlas a
échoué.

## Si vous choisissez le déploiement piloté par la CI

### 1. Couper l'auto-déploiement de Render

> Dashboard Render → votre service → **Settings** → **Auto-Deploy** → `Off`

### 2. Récupérer le Deploy Hook

> Dashboard Render → votre service → **Settings** → **Deploy Hook** → copier l'URL

### 3. L'enregistrer comme secret GitHub

> GitHub → dépôt → **Settings** → **Secrets and variables** → **Actions** →
> **New repository secret**

| Nom | Valeur |
|---|---|
| `RENDER_DEPLOY_HOOK_URL` | l'URL copiée à l'étape 2 |

Et, dans l'onglet **Variables** (nécessaire si votre URL diffère de la valeur
par défaut) :

| Nom | Valeur |
|---|---|
| `API_URL` | `https://<votre-service>.onrender.com` |

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
