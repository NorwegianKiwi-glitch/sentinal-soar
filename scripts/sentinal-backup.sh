#!/usr/bin/env bash
# On-demand backup: SQL-dump every running database container, then snapshot
# app data, CasaOS definitions, docker volumes, and the dumps into the
# encrypted restic repository at /DATA/Backups/restic-repo.
#
# Sentinal runs this automatically before every major upgrade (inside its
# container, which bind-mounts this script and the same paths). Manual runs:
#   sudo /usr/local/bin/sentinal-backup.sh
# Documentation: BACKUPS.md in the sentinal-soar repo.
set -euo pipefail
TAG="${1:-manual}"
export RESTIC_REPOSITORY=/DATA/Backups/restic-repo
export RESTIC_PASSWORD_FILE=/root/.config/sentinal-backup/password
DUMP_DIR=/DATA/Backups/db-dumps
mkdir -p "$DUMP_DIR"

echo "=== sentinal-backup ($TAG) $(date -Is) ==="

docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /postgres/ {print $1}' | while read -r name; do
  user=$(docker exec "$name" sh -c 'echo "${POSTGRES_USER:-postgres}"')
  echo "dumping postgres: $name (user $user)"
  docker exec "$name" pg_dumpall -U "$user" | gzip > "$DUMP_DIR/$name.sql.gz"
done

docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /mariadb|mysql/ {print $1}' | while read -r name; do
  echo "dumping mariadb/mysql: $name"
  docker exec "$name" sh -c 'exec mariadb-dump --all-databases -uroot -p"${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}"' \
    | gzip > "$DUMP_DIR/$name.sql.gz"
done

restic backup \
  /DATA/AppData \
  /var/lib/casaos/apps \
  /var/lib/docker/volumes \
  "$DUMP_DIR" \
  --tag "$TAG"

# Small single SSD: backups exist to survive upgrades, not as an archive.
# --group-by paths (not the default host+paths): every backup runs from a
# container whose hostname changes on each rebuild, so the default grouping
# made each snapshot its own group and keep-last-3 never pruned anything.
# All runs snapshot the same paths, so this collapses them into one group.
restic forget --group-by paths --keep-last 3 --prune
echo "=== done $(date -Is) ==="
