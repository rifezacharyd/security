FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only what the runtime needs.
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip \
 && pip install .

# Non-root runtime user.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin zdr \
 && chown -R zdr:zdr /app
USER zdr

EXPOSE 8080

ENV ZDR_HOST=0.0.0.0 \
    ZDR_PORT=8080

CMD ["zdr-feed"]
