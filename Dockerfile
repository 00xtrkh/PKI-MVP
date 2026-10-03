# MiniPKI web app
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MINIPKI_HOST=0.0.0.0 \
    MINIPKI_PORT=5000 \
    MINIPKI_DEBUG=0 \
    MINIPKI_STORAGE_DIR=/data

WORKDIR /app

# cryptography needs these for wheels; slim is enough on bookworm for manylinux wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app

USER appuser

EXPOSE 5000

VOLUME ["/data"]

CMD ["python", "-m", "pki.web"]
