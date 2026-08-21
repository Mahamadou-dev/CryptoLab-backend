# CryptoLab — backend
#
# Image de developpement local, consommee par docker-compose.yml a la racine.
# Le deploiement reel (Render) n'utilise pas cette image : voir DEPLOYMENT.md.

FROM python:3.12-slim

WORKDIR /app

# Les dependances changent moins souvent que le code : les installer d'abord
# maximise le cache Docker sur les rebuilds pendant le developpement.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# --reload : docker-compose monte le code en volume, le rechargement a chaud
# fonctionne donc comme en local.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
