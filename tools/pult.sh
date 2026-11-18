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
#   pult.sh page-answers <slug> [--since ISO]   # owner's answers inside a page (A128): {slug,key,version,updated_at,data}
#   pult.sh page-answers-all [--since ISO]      # the same over all pages
#   pult.sh reply-log  [N]                 # last N sends (default 20)
#   pult.sh new-token  <label>             # mint a pult token, print it ONCE (only sha256 is stored)
#   pult.sh tokens                         # label, created_at, revoked, hash prefix
#   pult.sh revoke-token <hash-prefix>     # 8+ hex chars of the hash, must match exactly one token
#
# The owner opens the pult by a personal link https://astrolytix.com/api/admin/pult/#k=<token>;
# the shell keeps the token in localStorage and sends it as X-Pult-Token.
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
CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, label TEXT, created_at TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS page_answers (slug TEXT, key TEXT, data TEXT, version INTEGER, updated_at TEXT, PRIMARY KEY(slug, key));
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
page-answers | page-answers-all)
	cond="1=1"
	if [ "$cmd" = "page-answers" ]; then
		[ $# -ge 1 ] && [ -n "$1" ] || die "usage: page-answers <slug> [--since ISO]"
		sl=$(vf "$1"); shift
		cond="slug = $(rf "$sl")"
	fi
	if [ $# -gt 0 ]; then
		[ "$1" = "--since" ] && [ $# -eq 2 ] && [ -n "$2" ] || die "usage: $cmd${sl:+ <slug>} [--since ISO]"
		s=$(vf "$2")
		cond="$cond AND updated_at >= $(rf "$s")"
	fi
	q "SELECT json_object('slug',slug,'key',key,'version',version,'updated_at',updated_at,'data',json(data)) FROM page_answers
WHERE $cond ORDER BY slug, updated_at, key;"
	;;
reply-log)
	lim="${1:-20}"
	[[ "$lim" =~ ^[0-9]{1,6}$ ]] || die "N must be a number"
	q "SELECT json_object('n',n,'id',id,'at',at,'data',json(data)) FROM
(SELECT * FROM reply_log ORDER BY n DESC LIMIT $lim) ORDER BY n;"
	;;
new-token)
	[ $# -eq 1 ] && [ -n "$1" ] || die "usage: new-token <label>"
	tok=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	[[ "$tok" =~ ^[0-9a-f]{64}$ ]] || die "random token generation failed"
	if command -v sha256sum >/dev/null 2>&1; then
		h=$(printf '%s' "$tok" | sha256sum | cut -d' ' -f1)
	else
		h=$(printf '%s' "$tok" | shasum -a 256 | cut -d' ' -f1)
	fi
	[[ "$h" =~ ^[0-9a-f]{64}$ ]] || die "sha256 failed"
	lb=$(vf "$1")
	q "INSERT INTO tokens(hash, label, created_at, revoked) VALUES('$h', $(rf "$lb"), $NOW, 0);"
	# the only time the token is shown; it is not stored anywhere
	echo "{\"token\":\"$tok\",\"hash8\":\"${h:0:8}\",\"link\":\"https://astrolytix.com/api/admin/pult/#k=$tok\"}"
	;;
tokens)
	q "SELECT json_object('hash8',substr(hash,1,8),'label',label,'created_at',created_at,'revoked',revoked)
FROM tokens ORDER BY created_at, hash;"
	;;
revoke-token)
	[ $# -eq 1 ] || die "usage: revoke-token <hash-prefix>"
	[[ "$1" =~ ^[0-9a-f]{8,64}$ ]] || die "hash prefix: 8..64 lowercase hex chars"
	cnt=$(q "SELECT COUNT(*) FROM tokens WHERE substr(hash,1,${#1}) = '$1';")
	[ "$cnt" = "1" ] || die "prefix $1 matches $cnt tokens (need exactly 1)"
	must_change "UPDATE tokens SET revoked = 1 WHERE substr(hash,1,${#1}) = '$1';" "revoke failed: $1"
	;;
*)
	sed -n '2,27p' "$0" >&2
	exit 2
	;;
esac
