#!/usr/bin/env python3
"""Tests for tools/archive_ai_journals.py on a local SQLite copy: python3 tools/test_archive_ai_journals.py"""
import gzip
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import archive_ai_journals as aj  # noqa: E402


def make_db(path: Path) -> None:
    con = sqlite3.connect(path)
    now = datetime.now(timezone.utc)
    for t in ("ai_arbiter_events", "ai_guard_corpus"):
        con.execute(f"CREATE TABLE {t} (id INTEGER PRIMARY KEY AUTOINCREMENT, feature TEXT, created_at DATETIME)")
        for age in (60, 45, 31, 29, 1):
            con.execute(f"INSERT INTO {t} (feature, created_at) VALUES (?, ?)",
                        (f"f{age} «ру»", (now - timedelta(days=age)).strftime("%Y-%m-%d %H:%M:%S")))
    con.commit()
    con.close()


def counts(db: Path) -> dict:
    con = sqlite3.connect(db)
    out = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("ai_arbiter_events", "ai_guard_corpus")}
    con.close()
    return out


def test_dry_run_writes_nothing():
    with tempfile.TemporaryDirectory() as d:
        db, arc = Path(d) / "a.db", Path(d) / "arc"
        make_db(db)
        assert aj.main(["--local-db", str(db), "--archive-dir", str(arc), "--remote", ""]) == 0
        assert counts(db) == {"ai_arbiter_events": 5, "ai_guard_corpus": 5}
        assert not arc.exists()


def test_apply_archives_then_deletes_only_old_rows():
    with tempfile.TemporaryDirectory() as d:
        db, arc = Path(d) / "a.db", Path(d) / "arc"
        make_db(db)
        assert aj.main(["--apply", "--local-db", str(db), "--archive-dir", str(arc), "--remote", ""]) == 0
        assert counts(db) == {"ai_arbiter_events": 2, "ai_guard_corpus": 2}
        files = sorted(arc.glob("*.jsonl.gz"))
        assert len(files) == 2 and all((arc / (f.name + ".sha256")).exists() for f in files)
        rows = [json.loads(x) for x in gzip.open(files[0], "rt", encoding="utf-8")]
        assert [r["feature"] for r in rows] == ["f60 «ру»", "f45 «ру»", "f31 «ру»"]
        # second run the same day: nothing left to archive, existing files untouched
        assert aj.main(["--apply", "--local-db", str(db), "--archive-dir", str(arc), "--remote", ""]) == 0


def test_mismatch_stops_before_delete():
    with tempfile.TemporaryDirectory() as d:
        db, arc = Path(d) / "a.db", Path(d) / "arc"
        make_db(db)
        real = aj.verify_file
        aj.verify_file = lambda p: (0, 0)
        try:
            aj.main(["--apply", "--local-db", str(db), "--archive-dir", str(arc), "--remote", ""])
            raise AssertionError("expected Stop")
        except aj.Stop as e:
            assert "nothing deleted" in str(e)
        finally:
            aj.verify_file = real
        assert counts(db) == {"ai_arbiter_events": 5, "ai_guard_corpus": 5}


def test_delete_helper_refuses_changed_rows():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "a.db"
        make_db(db)
        box = aj.Box(str(db))
        cutoff = aj.cutoff_for(30)
        p = box.run("delete", str(db), "ai_guard_corpus", cutoff, "99", "2", "3")   # wrong n/id_sum
        assert p.returncode != 0 and b"nothing deleted" in p.stderr
        assert counts(db)["ai_guard_corpus"] == 5


def test_days_floor():
    try:
        aj.main(["--days", "3", "--local-db", "/nonexistent"])
        raise AssertionError("expected Stop")
    except aj.Stop:
        pass


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
