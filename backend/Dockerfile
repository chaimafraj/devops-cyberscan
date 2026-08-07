FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/home/cyberscan/.cache/huggingface

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        docker-cli \
        nmap \
        openssl \
        sslscan \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

RUN addgroup --system cyberscan \
    && adduser --system --ingroup cyberscan --home /home/cyberscan cyberscan \
    && mkdir -p /app/media/rapports /app/staticfiles $HF_HOME \
    && chown -R cyberscan:cyberscan /app /home/cyberscan

COPY --chown=cyberscan:cyberscan . .
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Entrypoint starts as root to create/chown bind-mounted media, then drops to cyberscan.
USER root

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD [gunicorn, backend.wsgi:application, --bind, 0.0.0.0:8000, --workers, 3, --timeout, 1800, --access-logfile, -, --error-logfile, -]
