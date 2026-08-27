FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/aegis/.local/bin:${PATH}

RUN groupadd --system --gid 10001 aegis \
    && useradd --system --uid 10001 --gid aegis --create-home aegis
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* && rm -rf /wheels

WORKDIR /app
COPY --chown=aegis:aegis migrations ./migrations
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/v1/health/live', timeout=2)"]

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header"]

