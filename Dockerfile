# Trivy and the docker CLI (with the compose plugin, used for confirm-gated
# major upgrades) are copied from their official images rather than installed
# via apt — keeps the runtime image small and version-pinned. Both are static
# Go binaries, so the alpine->debian jump is fine.
FROM aquasec/trivy:latest AS trivy
FROM docker:cli AS dockercli
FROM restic/restic:latest AS restic

FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=restic /usr/bin/restic /usr/local/bin/restic

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinal ./sentinal

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["python", "-m", "sentinal"]
