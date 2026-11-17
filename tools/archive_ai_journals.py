#!/usr/bin/env python3
"""A88 step 7: archive and trim the AI journals in analytics.db (ai_arbiter_events, ai_guard_corpus).

Runs on the Mac; the box is reached over ssh and every box command runs under nice -n19 / ionice -c3.

    python3 tools/archive_ai_journals.py                      # dry run: what would go, nothing written
    python3 tools/archive_ai_journals.py --days 60            # dry run with another retention
    python3 tools/archive_ai_journals.py --apply --days 30    # export → verify → Elements + gdrive-crypt → DELETE
    python3 tools/archive_ai_journals.py --vacuum             # VACUUM only (quiet hour; needs free ≥ 2× db)

Order per table (any mismatch = stop, nothing deleted):
  1. stat on the box: rows with created_at < cutoff → n, max(id), sum(id).
  2. export exactly `created_at < cutoff AND id <= max_id` as gzip JSONL straight to Elements
     (<archive>/<table>-before-<cutoff date>.jsonl.gz, never overwritten) + .sha256.
  3. read the file back from Elements: line count and id sum must equal the stat.
  4. rclone copyto gdrive-crypt:ai-journals/<name>; remote size must equal the local size.
  5. DELETE on the box with the same condition; the helper re-checks n/id sum before deleting.

Without VACUUM the freed pages are reused by new rows, so the file stops growing; VACUUM gives the
space back to the filesystem but locks the DB for its duration (astrolog-api busy_timeout is 5 s),
hence a separate flag for a quiet hour.

--local-db PATH runs the helper locally against a SQLite copy (tests); --archive-dir and --remote
override the destinations (tests use a temp dir and --remote '' to skip the cloud copy).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = HERE / "ai_journals_box.py"
BOX = "ruslan@91.98.77.205"
BOX_DB = "/home/ruslan/aia/server/analytics.db"
ARCHIVE = Path("/Volumes/Elements/aia-archive/ai-journals")
REMOTE = "gdrive-crypt:ai-journals"
ELEMENTS = Path.home() / ".claude/bin/elements"
SSH = ["ssh", "-o", "ConnectTimeout=20", "-o", "BatchMode=yes", BOX]


class Stop(SystemExit):
    pass


class Box:
    """Runs the helper either on the box over ssh or locally against a test DB."""

    def __init__(self, local_db: str | None):
        self.local = local_db
        self.db = local_db or BOX_DB

    def _cmd(self, *args: str) -> list[str]:
        if self.local:
            return [sys.executable, str(HELPER), *args]
        quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in args)
        return [*SSH, f"nice -n19 ionice -c3 python3 - {quoted}"]

    def run(self, *args: str, stdout=subprocess.PIPE) -> subprocess.CompletedProcess:
        stdin = None if self.local else HELPER.open("rb")
        try:
            return subprocess.run(self._cmd(*args), stdin=stdin, stdout=stdout, stderr=subprocess.PIPE)
        finally:
            if stdin:
                stdin.close()

    def json(self, *args: str) -> dict:
        p = self.run(*args)
        if p.returncode != 0:
            raise Stop(f"STOP: box {args[0]} failed: {p.stderr.decode().strip()}")
        return json.loads(p.stdout)


def cutoff_for(days: int, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    day = (now - timedelta(days=days)).date()
    return f"{day.isoformat()} 00:00:00"   # created_at is SQLite datetime('now'): UTC 'YYYY-MM-DD HH:MM:SS'


def check_elements(archive: Path) -> None:
    if str(archive).startswith("/Volumes/Elements"):
        p = subprocess.run([str(ELEMENTS), "status"], capture_output=True, text=True)
        if p.returncode != 0 or "СТОП" in p.stdout + p.stderr or "отвечает" not in p.stdout:
            raise Stop(f"STOP: Elements not ready:\n{p.stdout}{p.stderr}")
    archive.mkdir(parents=True, exist_ok=True)


def verify_file(path: Path) -> tuple[int, int]:
    n = s = 0
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            s += int(json.loads(line)["id"])
            n += 1
    return n, s


def cloud_copy(path: Path, remote: str) -> None:
    dest = f"{remote}/{path.name}"
    if subprocess.run(["rclone", "copyto", str(path), dest]).returncode != 0:
        raise Stop(f"STOP: rclone copyto {dest} failed")
    p = subprocess.run(["rclone", "lsjson", dest], capture_output=True, text=True)
    meta = json.loads(p.stdout or "[]") if p.returncode == 0 else []
    if not meta or int(meta[0]["Size"]) != path.stat().st_size:
        raise Stop(f"STOP: {dest} size differs from {path.stat().st_size}")


def archive_table(box: Box, table: str, st: dict, cutoff: str, archive: Path, remote: str) -> None:
    name = f"{table}-before-{cutoff[:10]}.jsonl.gz"
    path = archive / name
    if path.exists():
        # Resume after a failed cloud copy: the same-day file is reused only if it still matches the box exactly.
        got = verify_file(path)
        if got != (st["n"], st["id_sum"]):
            raise Stop(f"STOP: {path} exists with n={got[0]} id_sum={got[1]}, box n={st['n']} "
                       f"id_sum={st['id_sum']} — not overwriting, nothing deleted")
        print(f"{table}: reusing verified {path}")
    else:
        tmp = path.with_suffix(".gz.part")
        with tmp.open("wb") as f:
            p = box.run("export", box.db, table, cutoff, str(st["max_id"]), stdout=f)
        if p.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise Stop(f"STOP: export {table} failed: {p.stderr.decode().strip()}")
        got = verify_file(tmp)
        if got != (st["n"], st["id_sum"]):
            raise Stop(f"STOP: {tmp} has n={got[0]} id_sum={got[1]}, box n={st['n']} id_sum={st['id_sum']}; "
                       "nothing deleted")
        tmp.rename(path)
        print(f"{table}: archived {st['n']} rows → {path} ({path.stat().st_size} B)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (archive / (name + ".sha256")).write_text(f"{digest}  {name}\n")
    if remote:
        cloud_copy(path, remote)
        print(f"{table}: copied to {remote}/{name}")
    p = box.run("delete", box.db, table, cutoff, str(st["max_id"]), str(st["n"]), str(st["id_sum"]))
    if p.returncode != 0:
        raise Stop(f"STOP: delete {table}: {p.stderr.decode().strip()}")
    print(f"{table}: {p.stdout.decode().strip()}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--days", type=int, default=30, help="keep this many days on the box (default 30, owner 17.11.2026)")
    ap.add_argument("--apply", action="store_true", help="export, verify, copy and DELETE (default: dry run)")
    ap.add_argument("--vacuum", action="store_true", help="VACUUM only (quiet hour)")
    ap.add_argument("--local-db", help="test mode: a local SQLite file instead of the box")
    ap.add_argument("--archive-dir", type=Path, default=ARCHIVE)
    ap.add_argument("--remote", default=REMOTE, help="rclone destination; '' skips the cloud copy")
    a = ap.parse_args(argv)
    if a.days < 15:   # weekly_report.py compares with the previous week: reads 14 days back (+1 day margin)
        raise Stop("STOP: --days below 15 would cut into the weekly report's previous-week window")
    box = Box(a.local_db)
    cutoff = cutoff_for(a.days)
    st = box.json("stat", box.db, cutoff)
    print(f"db {st['db_bytes'] / 2**20:.0f} MiB, free {st['free_bytes'] / 2**20:.0f} MiB, cutoff {cutoff} UTC")
    for t, s in st["tables"].items():
        print(f"  {t}: {s['n']} of {s['total']} rows older than cutoff (oldest {s['oldest']}), max_id {s['max_id']}")

    if a.vacuum:
        if st["free_bytes"] < 2 * st["db_bytes"]:
            raise Stop("STOP: free space below 2× db size — no VACUUM")
        r = box.json("vacuum", box.db)
        print(f"VACUUM: {r['before'] / 2**20:.0f} → {r['after'] / 2**20:.0f} MiB")
        return 0
    if not a.apply:
        print("dry run — nothing written (add --apply)")
        return 0
    todo = {t: s for t, s in st["tables"].items() if s["n"] > 0}
    if not todo:
        print("nothing older than cutoff")
        return 0
    check_elements(a.archive_dir)
    for t, s in todo.items():
        archive_table(box, t, s, cutoff, a.archive_dir, a.remote)
    return 0


if __name__ == "__main__":
    sys.exit(main())
