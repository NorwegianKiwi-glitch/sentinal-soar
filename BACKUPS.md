# Backups

Backups of everything the Pi's apps care about, taken exactly when they
matter. Deliberately **not** on a schedule: the Pi has one small SSD, so
snapshots exist to survive upgrades, not to be an archive. Set up
2026-07-12; lives entirely on the Pi.

## What gets backed up, and when

Backups run at two moments:

- **Automatically, as step one of every Major Upgrade** — Sentinal takes a
  snapshot before touching anything, refuses to upgrade if the backup fails,
  and prints the snapshot id in the Discord result and the scan log.
- **Manually, whenever you want one:** `sudo /usr/local/bin/sentinal-backup.sh`

Each run of `/usr/local/bin/sentinal-backup.sh`:

1. **SQL-dumps every running database container** (anything whose image looks
   like postgres/mariadb/mysql) into `/DATA/Backups/db-dumps/<container>.sql.gz`
   using `pg_dumpall` / `mariadb-dump`. These are consistent dumps taken while
   the databases run — the gold standard for restoring a database.
2. **Snapshots these paths into an encrypted restic repository:**
   - `/DATA/AppData` — all CasaOS app data (immich photo library and pgdata,
     nextcloud, vaultwarden, …) — ~42 GB, deduplicated across snapshots
   - `/var/lib/casaos/apps` — every app's compose definition
   - `/var/lib/docker/volumes` — docker named volumes
   - `/DATA/Backups/db-dumps` — the SQL dumps from step 1
3. **Applies retention**: keeps only the **last 3 snapshots**, pruning the
   rest — bounded disk use on the single small SSD.

Because restic deduplicates, a new snapshot of 42 GB only stores what
actually changed since the previous one.

## Where everything lives

| Thing | Location |
|---|---|
| Restic repository (the backups) | `/DATA/Backups/restic-repo` |
| Latest SQL dumps | `/DATA/Backups/db-dumps/` |
| Backup script | `/usr/local/bin/sentinal-backup.sh` |
| Output of Sentinal-triggered runs | the upgrade's Discord/scan-log entry (snapshot id) and `docker logs sentinal-soar-app-1` |
| Repository password | `/root/.config/sentinal-backup/password` |

> ⚠️ **Copy the repository password into Vaultwarden now**
> (`sudo cat /root/.config/sentinal-backup/password`). The repository is
> encrypted; if the Pi's disk dies AND you don't have the password stored
> elsewhere, the backups are unreadable. This is the one thing the backup
> can't protect for you.

> ⚠️ **Single-disk caveat:** backups live on the same physical disk as the
> data. They protect against botched upgrades, accidental deletion, and
> database corruption — not against the disk itself dying. An offsite copy
> (restic supports S3/Backblaze/rclone targets natively) is the natural next
> step.

## Everyday commands

```bash
sudo /usr/local/bin/sentinal-backup.sh         # run a backup right now
sudo sentinal-restic snapshots                 # list all snapshots (tags show why each exists)
sudo sentinal-restic ls latest | less          # browse the newest snapshot
sudo sentinal-restic check                     # verify repository integrity (do this monthly)
```

`sentinal-restic` is a thin wrapper that points plain restic at the right
repository and password file — every normal restic command works through it.

You do **not** need to back up before a Major Upgrade — the button does it
for you and shows the snapshot id in its result message. Use that id in the
restore commands below instead of `latest` when newer snapshots exist.

## Restore: the immich upgrade went wrong

This is the scenario the backups exist for. Sentinal already auto-restores
the compose *definition* if `compose up` itself fails — the steps below are
for when the new version started but is broken (won't boot cleanly, migration
crashed halfway, app misbehaves).

**1. Stop the app:**

```bash
sudo docker compose -f /var/lib/casaos/apps/big-bear-immich/docker-compose.yml down
```

**2. Put the definition back on the old version** (pick either):

```bash
# Sentinal's pre-upgrade copy:
sudo cp /var/lib/casaos/apps/big-bear-immich/docker-compose.yml.sentinal-bak \
        /var/lib/casaos/apps/big-bear-immich/docker-compose.yml
# …or from last night's snapshot:
sudo sentinal-restic restore latest --target / \
     --include /var/lib/casaos/apps/big-bear-immich/docker-compose.yml
```

**3. Restore the database** (the part a failed migration corrupts). Immich's
postgres data dir is `/DATA/AppData/big-bear-immich/pgdata`, its compose
service is called `database`, and its superuser is `casaos`:

```bash
# get the pre-upgrade SQL dump out of the snapshot
sudo sentinal-restic restore latest --target /tmp/restore \
     --include /DATA/Backups/db-dumps/immich-postgres.sql.gz

# move the broken data dir aside and start an empty database on the OLD image
sudo mv /DATA/AppData/big-bear-immich/pgdata /DATA/AppData/big-bear-immich/pgdata.broken
sudo docker compose -f /var/lib/casaos/apps/big-bear-immich/docker-compose.yml up -d database
sleep 15

# load the dump
gunzip -c /tmp/restore/DATA/Backups/db-dumps/immich-postgres.sql.gz \
  | docker exec -i immich-postgres psql -U casaos -d postgres
```

**4. Photos:** a failed upgrade does not delete your library — the `upload`
directory normally needs no restore. If it ever does:

```bash
sudo sentinal-restic restore <snapshot-id> --target / \
     --include /DATA/AppData/big-bear-immich/upload
```

**5. Start the app and verify:**

```bash
sudo docker compose -f /var/lib/casaos/apps/big-bear-immich/docker-compose.yml up -d
docker ps --filter name=immich --format '{{.Names}} {{.Status}}'
```

Once immich looks healthy again, clean up `pgdata.broken` and `/tmp/restore`.

## Restore: any other app, or single files

The same pattern works for everything — find the path, restore it:

```bash
sudo sentinal-restic snapshots                          # pick a snapshot (or use "latest")
sudo sentinal-restic ls latest /DATA/AppData/vaultwarden | head
sudo sentinal-restic restore latest --target /tmp/restore \
     --include /DATA/AppData/vaultwarden
```

Restoring `--target /` writes files back to their original locations —
stop the affected app first. Restoring to `/tmp/restore` lets you inspect
and copy selectively.

For databases, always prefer loading the `.sql.gz` dump into a fresh
database over raw-copying a pgdata directory: dumps restore cleanly across
image versions; raw data dirs only work on the exact same major version.
