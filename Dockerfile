# Trivy binary is copied from Aqua's official image rather than installed via
# apt inside this image — keeps the runtime image small and version-pinned.
FROM aquasec/trivy:latest AS trivy

FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinal ./sentinal

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["python", "-m", "sentinal"]
