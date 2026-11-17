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
  vacuum <db>                           -> VACUUM (caller checks free space first); prints size before/after

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
    cur = con.execute(f"SELECT * FROM {_table(table)} WHERE {WHERE} ORDER BY id", (cutoff, int(max_id)))
    with gzip.GzipFile(fileobj=sys.stdout.buffer, mode="wb", compresslevel=6) as gz:
        for row in cur:
            gz.write(json.dumps(dict(row), ensure_ascii=False).encode() + b"\n")
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


def vacuum(db):
    before = os.path.getsize(db)
    con = sqlite3.connect(db, timeout=60, isolation_level=None)
    con.execute("VACUUM")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    print(json.dumps({"before": before, "after": os.path.getsize(db)}))


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"stat": stat, "export": export, "delete": delete, "vacuum": vacuum}[cmd](*args)
