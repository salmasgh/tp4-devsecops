# syntax=docker/dockerfile:1
# Dockerfile sécurisé (TP4) – multi-stage, image minimale, non-root

# ---- Étape 1 : installation des dépendances (outils de build isolés) ----
FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Étape 2 : image d'exécution minimale ----
FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
LABEL org.opencontainers.image.title="tp4-app" \
      org.opencontainers.image.description="API FastAPI durcie - TP4 DevSecOps"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/app.db
# Mises à jour de sécurité, suppression de pip (inutile au runtime),
# création d'un utilisateur système sans shell ni home
RUN apk upgrade --no-cache \
    && pip uninstall -y pip \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app -s /sbin/nologin app \
    && mkdir -p /data && chown app:app /data
COPY --from=builder /install /usr/local
WORKDIR /app
# Code en lecture seule pour l'utilisateur applicatif (propriétaire root)
COPY main.py .
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
