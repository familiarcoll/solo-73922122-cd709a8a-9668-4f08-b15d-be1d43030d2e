FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Container-internal default; docker-compose injects the real secrets via env_file.
ENV AUTH_DB_PATH=/data/auth.db \
    ACCESS_TOKEN_TTL=60 \
    REFRESH_TOKEN_TTL=600 \
    IDEMPOTENCY_TTL=30

EXPOSE 8000

# A plain exec-form uvicorn command; no shell, no secret on any command line.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
