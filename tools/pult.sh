#!/usr/bin/env bash
# A124 — owner's pult store (pult.db) from the shell, ON THE BOX over ssh.
# No HTTP, no secrets: talks to pult.db directly with the sqlite3 CLI.
# Every user-supplied value (ids, JSON, html, dates) goes into SQL through a
# temp file + readfile(), never spliced into the SQL text.
#
#   pult.sh items
#   pult.sh replies [--since ISO]
#   pult.sh general [--new]
#   pult.sh set-item   <id> <json-file>    # replace block data, version+1
#   pult.sh patch-item <id> <json-file>    # top-level merge (json_patch; a null value deletes the key), version+1
#   pult.sh handled    <general-id>        # general[id].handled = true
#   pult.sh put-page   <slug> <title> <session> <html-file>
#   pult.sh pages
#   pult.sh reply-log  [N]                 # last N sends (default 20)
#
# DB path: $PULT_DB, default = the file the server opens (./pult.db in the
# server dir, i.e. one level above this tools/ directory).
# Output: one JSON object per line.
set -euo pipefail

die() { echo "pult.sh: $*" >&2; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 not found"

DB="${PULT_DB:-$(cd "$(dirname "$0")/.." && pwd)/pult.db}"

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/pult.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT
# vf <value> → path of a fresh temp file holding the value (mktemp path: no quotes
# inside). Called in $(…) subshells, so every value gets its own mktemp file.
vf() { local f; f=$(mktemp "$TMPD/v.XXXXXX"); printf '%s' "$1" >"$f"; printf '%s' "$f"; }
# rf <path> → SQL expression reading that file as TEXT
rf() { printf "CAST(readfile('%s') AS TEXT)" "$1"; }

need_file() { [ -f "$1" ] && [ -r "$1" ] || die "cannot read file: $1"; }

q() {
	sqlite3 -bail -batch -noheader "$DB" <<SQL
.timeout 5000
CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS general (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS pages (slug TEXT PRIMARY KEY, title TEXT, session TEXT, html TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS reply_log (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, data TEXT, at TEXT);
$1
SQL
}

NOW="strftime('%Y-%m-%dT%H:%M:%SZ','now')"

# the row must exist: the statement's last line prints changes()
must_change() {
	local out
	out=$(q "$1
SELECT changes();")
	[ "$out" = "1" ] || die "$2"
	echo "{\"ok\":true}"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
items)
	q "SELECT json_object('id',id,'version',version,'updated_at',updated_at,'data',json(data)) FROM items ORDER BY id;"
	;;
replies)
	if [ "${1:-}" = "--since" ]; then
		[ -n "${2:-}" ] || die "--since needs an ISO time"
		s=$(vf "$2")
		q "SELECT json_object('id',id,'version',version,'updated_at',updated_at,'data',json(data)) FROM replies
WHERE updated_at >= $(rf "$s") ORDER BY updated_at, id;"
	else
		q "SELECT json_object('id',id,'version',version,'updated_at',updated_at,'data',json(data)) FROM replies ORDER BY updated_at, id;"
	fi
	;;
general)
	where=""
	[ "${1:-}" = "--new" ] && where="WHERE COALESCE(json_extract(data,'\$.handled'),0) = 0"
	q "SELECT json_object('id',id,'version',version,'updated_at',updated_at,'data',json(data)) FROM general $where ORDER BY updated_at, id;"
	;;
set-item | patch-item)
	[ $# -eq 2 ] || die "usage: $cmd <id> <json-file>"
	[ -n "$1" ] || die "empty id"
	need_file "$2"
	id=$(vf "$1")
	js=$(rf "$2")
	# json() rejects malformed JSON (-bail stops); only objects are blocks
	[ "$(q "SELECT json_type(json($js));")" = "object" ] || die "$2: JSON object expected"
	if [ "$cmd" = "set-item" ]; then
		q "INSERT INTO items(id, data, version, updated_at) VALUES($(rf "$id"), json($js), 1, $NOW)
ON CONFLICT(id) DO UPDATE SET data = excluded.data, version = items.version + 1, updated_at = excluded.updated_at;"
		echo "{\"ok\":true}"
	else
		must_change "UPDATE items SET data = json_patch(COALESCE(data,'{}'), json($js)), version = COALESCE(version,0) + 1,
updated_at = $NOW WHERE id = $(rf "$id");" "no such item: $1"
	fi
	;;
handled)
	[ $# -eq 1 ] && [ -n "$1" ] || die "usage: handled <general-id>"
	id=$(vf "$1")
	must_change "UPDATE general SET data = json_set(COALESCE(data,'{}'), '\$.handled', json('true')),
version = COALESCE(version,0) + 1, updated_at = $NOW WHERE id = $(rf "$id");" "no such general: $1"
	;;
put-page)
	[ $# -eq 4 ] || die "usage: put-page <slug> <title> <session> <html-file>"
	[[ "$1" =~ ^[A-Za-z0-9._-]{1,120}$ ]] || die "bad slug (A-Za-z0-9._- up to 120): $1"
	need_file "$4"
	sl=$(vf "$1"); ti=$(vf "$2"); se=$(vf "$3")
	q "INSERT INTO pages(slug, title, session, html, updated_at)
VALUES($(rf "$sl"), $(rf "$ti"), $(rf "$se"), $(rf "$4"), $NOW)
ON CONFLICT(slug) DO UPDATE SET title = excluded.title, session = excluded.session, html = excluded.html,
updated_at = excluded.updated_at;"
	echo "{\"ok\":true,\"url\":\"/api/admin/pult/#p/$1\"}"
	;;
pages)
	q "SELECT json_object('slug',slug,'title',title,'session',session,'updated_at',updated_at,'bytes',length(html))
FROM pages ORDER BY updated_at DESC, slug;"
	;;
reply-log)
	lim="${1:-20}"
	[[ "$lim" =~ ^[0-9]{1,6}$ ]] || die "N must be a number"
	q "SELECT json_object('n',n,'id',id,'at',at,'data',json(data)) FROM
(SELECT * FROM reply_log ORDER BY n DESC LIMIT $lim) ORDER BY n;"
	;;
*)
	sed -n '2,19p' "$0" >&2
	exit 2
	;;
esac
