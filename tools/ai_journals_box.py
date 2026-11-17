#!/usr/bin/env python3
"""Box-side helper for tools/archive_ai_journals.py (A88 step 7).

Runs next to analytics.db (sent over ssh stdin as `python3 - <cmd> ...`, or run
directly against a local copy in tests). Stdlib only. Commands:

  stat   <db> <cutoff>                  -> JSON: per-table count/max_id/id_sum of rows older than cutoff,
                                           db size, free bytes on the db filesystem
  export <db> <table> <cutoff> <max_id> -> gzip(JSONL) of the selected rows on stdout
  delete <db> <table> <cutoff> <max_id> <expect_n> <expect_sum>
                                        -> deletes exactly those rows in small batches; refuses if the
                                           pre-count/id-sum differ from what was archived
  vacuum <db> [--max-s S] [--until HH:MM] [--radio-root P]
                                        -> quiet-moment VACUUM under a watchdog; JSON lines before/after

Row selection is always `created_at < cutoff AND id <= max_id`, so rows written
after the stat call are never touched.
"""
import gzip
import json
import os
import sqlite3
import sys

TABLES = ("ai_arbiter_events", "ai_guard_corpus")
WHERE = "created_at < ? AND id <= ?"
BATCH = 500
CALL_STALE_S = 900      # as scripts/radio_feeder.py in insta-agent: an older live call is abandoned
RETRY_S = 900


def _table(name):
    if name not in TABLES:
        sys.exit(f"unknown table {name!r}")
    return name


def _ro(db):
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)


def stat(db, cutoff):
    con = _ro(db)
    out = {"db_bytes": os.path.getsize(db), "tables": {}}
    for t in TABLES:
        n, mx, s = con.execute(
            f"SELECT count(*), coalesce(max(id), 0), coalesce(sum(id), 0) FROM {t} WHERE created_at < ?",
            (cutoff,)).fetchone()
        total, oldest = con.execute(f"SELECT count(*), min(created_at) FROM {t}").fetchone()
        out["tables"][t] = {"n": n, "max_id": mx, "id_sum": s, "total": total, "oldest": oldest}
    st = os.statvfs(os.path.dirname(os.path.abspath(db)))
    out["free_bytes"] = st.f_bavail * st.f_frsize
    con.close()
    json.dump(out, sys.stdout)


def export(db, table, cutoff, max_id):
    con = _ro(db)
    con.row_factory = sqlite3.Row
    # Some rows hold invalid UTF-8 (answers cut mid-character). Keep them byte-exact: undecodable bytes become
    # lone surrogates, written as \udcXX escapes in ASCII JSON; restore with s.encode("utf-8", "surrogateescape").
    con.text_factory = lambda b: b.decode("utf-8", "surrogateescape")
    cur = con.execute(f"SELECT * FROM {_table(table)} WHERE {WHERE} ORDER BY id", (cutoff, int(max_id)))
    with gzip.GzipFile(fileobj=sys.stdout.buffer, mode="wb", compresslevel=6) as gz:
        for row in cur:
            gz.write(json.dumps(dict(row), ensure_ascii=True).encode("ascii") + b"\n")
    con.close()


def delete(db, table, cutoff, max_id, expect_n, expect_sum):
    t, max_id, expect_n, expect_sum = _table(table), int(max_id), int(expect_n), int(expect_sum)
    con = sqlite3.connect(db, timeout=30, isolation_level=None)
    n, s = con.execute(f"SELECT count(*), coalesce(sum(id), 0) FROM {t} WHERE {WHERE}", (cutoff, max_id)).fetchone()
    if (n, s) != (expect_n, expect_sum):
        sys.exit(f"STOP {t}: on box n={n} id_sum={s}, archived n={expect_n} id_sum={expect_sum}; nothing deleted")
    deleted = 0
    while True:
        # Short write transactions: astrolog-api keeps inserting (busy_timeout 5 s).
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute(
            f"DELETE FROM {t} WHERE id IN (SELECT id FROM {t} WHERE {WHERE} ORDER BY id LIMIT {BATCH})",
            (cutoff, max_id))
        con.execute("COMMIT")
        if cur.rowcount <= 0:
            break
        deleted += cur.rowcount
    con.close()
    print(json.dumps({"table": t, "deleted": deleted}))
    if deleted != expect_n:
        sys.exit(f"STOP {t}: deleted {deleted}, expected {expect_n}")


def _air_busy(con, radio_root, now):
    """Why VACUUM should wait now, or '' — live radio call (as radio_restart.call_live sees it) or voice in chats."""
    try:
        doc = json.loads(open(os.path.join(radio_root, "call", "now.json")).read())
        if doc.get("state") == "live" and now - float(doc.get("updated", 0)) <= CALL_STALE_S:
            return "live radio call"
    except (OSError, ValueError, TypeError):
        pass
    try:
        n = con.execute("SELECT count(*) FROM speech_usage WHERE created_at >= datetime(?, 'unixepoch', '-10 minutes')",
                        (int(now),)).fetchone()[0]
    except sqlite3.OperationalError:          # no speech_usage table yet
        n = 0
    return f"{n} voice requests in the last 10 min" if n else ""


def _sizes(db):
    st = os.statvfs(os.path.dirname(os.path.abspath(db)))
    wal = db + "-wal"
    return {"free": st.f_bavail * st.f_frsize, "db": os.path.getsize(db),
            "wal": os.path.getsize(wal) if os.path.exists(wal) else 0}


def vacuum(db, *opts):
    """VACUUM in a quiet moment, under a watchdog (A88 step 7, coordinator 17.11):
    waits (RETRY_S) while a radio call is live or voice was used in the last 10 min, gives up after --until (UTC
    HH:MM, today); needs free ≥ 2× (db + wal); a VACUUM longer than --max-s is interrupted (SQLite rolls back)."""
    import argparse
    import time
    from datetime import datetime, timezone
    ap = argparse.ArgumentParser(prog="vacuum")
    ap.add_argument("--max-s", type=float, default=300)
    ap.add_argument("--until", default="03:15")
    ap.add_argument("--radio-root", default="/var/www/html/radio")
    ap.add_argument("--retry-s", type=float, default=RETRY_S)
    a = ap.parse_args(opts)
    hh, mm = map(int, a.until.split(":"))
    deadline = datetime.now(timezone.utc).replace(hour=hh, minute=mm, second=0, microsecond=0).timestamp()
    con = sqlite3.connect(db, timeout=60, isolation_level=None)
    while True:
        why = _air_busy(con, a.radio_root, time.time())
        if not why:
            break
        if time.time() + a.retry_s > deadline:
            con.close()
            sys.exit(f"STOP: {why}; next try would pass {a.until} UTC — no VACUUM")
        print(json.dumps({"wait": why, "retry_s": a.retry_s}), flush=True)
        time.sleep(a.retry_s)
    before = _sizes(db)
    if before["free"] < 2 * (before["db"] + before["wal"]):
        con.close()
        sys.exit(f"STOP: free {before['free']} B below 2x (db + wal) — no VACUUM")
    print(json.dumps({"before": before}), flush=True)
    t0 = time.monotonic()
    con.set_progress_handler(lambda: 1 if time.monotonic() - t0 > a.max_s else 0, 1000)
    try:
        con.execute("VACUUM")
    except sqlite3.OperationalError as e:      # "interrupted": the watchdog fired, SQLite rolled the VACUUM back
        con.close()
        sys.exit(f"STOP: VACUUM stopped after {time.monotonic() - t0:.1f} s ({e}); database unchanged")
    took = time.monotonic() - t0
    con.set_progress_handler(None, 0)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    print(json.dumps({"after": _sizes(db), "vacuum_s": round(took, 1)}), flush=True)


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"stat": stat, "export": export, "delete": delete, "vacuum": vacuum}[cmd](*args)
