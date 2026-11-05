#!/usr/bin/env bash
# A disposable PostgreSQL for the tests of the connector and the end-to-end
# test, on the host, without root, containers or a virtual machine:
#
#   test/harness/postgres.sh up        start it (idempotent) and print its DSNs
#   test/harness/postgres.sh env       print the DSNs as export lines, for eval
#   test/harness/postgres.sh run CMD   run CMD with the DSNs in its environment
#   test/harness/postgres.sh status
#   test/harness/postgres.sh stop      stop it, keeping its data (up restarts it)
#   test/harness/postgres.sh down      stop it and delete its data
#
# e.g. test/harness/postgres.sh run make test, or
# eval "$(test/harness/postgres.sh env)". The DSNs are those of the tests:
#
#   SHAWK_TEST_POSTGRES_DSN  postgres://postgres:PASSWORD@127.0.0.1:PORT/postgres
#   SHAWK_E2E_POSTGRES_DSN   postgres://postgres:PASSWORD@127.0.0.1:PORT/shawke2e
#
# The server is PostgreSQL 16, as in CI, from the relocatable builds of
# zonky embedded-postgres-binaries on Maven Central for darwin and linux
# (amd64, arm64), pinned by their SHA-256. They hold initdb, pg_ctl and
# postgres, not psql. Its data is in build/harness/postgres of the
# workspace; it listens on 127.0.0.1 only, on a port of the workspace (see
# free_port in lib.sh), without a Unix socket. The superuser postgres has a
# random password, kept in build/harness/postgres/password (0600): the
# loopback is shared with the other users of the host and, through the
# address of the host, with its VMs. Durability is off (fsync,
# full_page_writes) for speed.
#
# initdb refuses to run as root; run it as a user. On macOS, the sandbox of
# an agent such as Claude Code denies the System V shared memory that
# PostgreSQL needs, so run it outside the sandbox there.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

VERSION=16.15.0
MAVEN=https://repo1.maven.org/maven2/io/zonky/test/postgres
DIR="$STATE/postgres"
DATA="$DIR/data"

# binaries: prints the directory of the binaries of PostgreSQL, downloading
# and extracting them once to the cache.
binaries() {
	local plat sum jar bin tmp
	plat="$(platform)"
	case "$plat" in
	darwin-arm64) plat=darwin-arm64v8 sum=65b953905f0a4d46030767a6b44a52360170d69a7985f1b02aa435f2f6256a83 ;;
	darwin-amd64) sum=1229188b99515d2160d5cb6222bc96d9c5f3a248268df3bc2dfe0047e6c233d8 ;;
	linux-arm64) plat=linux-arm64v8 sum=f846a9989d686b7977d6eca9bc9d8b2b69e3f70c7eb60e032197d9c574a6136c ;;
	linux-amd64) sum=653abc065c682b85d3da50168fb95dc524bd85426cdec9ce3695a550ef431df2 ;;
	esac
	bin="$CACHE/postgres/$VERSION-$plat"
	if [[ ! -x "$bin/bin/postgres" ]]; then
		jar="$(fetch "$MAVEN/embedded-postgres-binaries-$plat/$VERSION/embedded-postgres-binaries-$plat-$VERSION.jar" "$sum")"
		mkdir -p "$CACHE/postgres"
		tmp="$(mktemp -d "$CACHE/postgres/.extract.XXXXXX")"
		# The jar is a zip archive that holds one archive, postgres-*.txz.
		if command -v unzip >/dev/null; then
			unzip -p "$jar" 'postgres-*.txz' | tar -xJf - -C "$tmp"
		else
			bsdtar -xOf "$jar" 'postgres-*.txz' | tar -xJf - -C "$tmp"
		fi
		[[ -x "$tmp/bin/postgres" ]] || die "no bin/postgres in $jar"
		# Renamed whole, so that no one sees a partial copy; another workspace
		# sharing the cache may have done it meanwhile.
		[[ -e "$bin" ]] || mv "$tmp" "$bin" 2>/dev/null || true
		rm -rf "$tmp"
		[[ -x "$bin/bin/postgres" ]] || die "no PostgreSQL in $bin; remove it and try again"
	fi
	echo "$bin/bin"
}

running() { [[ -f "$DATA/postmaster.pid" ]] && "$(binaries)/pg_ctl" -D "$DATA" status >/dev/null 2>&1; }

port() {
	[[ -f "$DIR/port" ]] || die "PostgreSQL is not running: run test/harness/postgres.sh up"
	cat "$DIR/port"
}

env_lines() {
	local port password
	port="$(port)"
	password="$(cat "$DIR/password")"
	# No parameters: sslmode=disable makes the role-switching test fail
	# (TestPGLearnedAsConnectorRole appends options to the DSN), and the
	# server has no TLS, which pgx then does without.
	echo "export SHAWK_TEST_POSTGRES_DSN=postgres://postgres:$password@127.0.0.1:$port/postgres"
	echo "export SHAWK_E2E_POSTGRES_DSN=postgres://postgres:$password@127.0.0.1:$port/shawke2e"
}

# init: makes the cluster, unless a previous run completed it.
init() {
	local bin=$1
	[[ -f "$DIR/initialized" ]] && return
	rm -rf "$DATA" "$DIR/password"
	mkdir -p "$DIR"
	chmod 0700 "$DIR"
	log "initializing $DATA"
	(umask 077 && head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$DIR/password")
	"$bin/initdb" -D "$DATA" -U postgres -A scram-sha-256 --pwfile="$DIR/password" -E UTF8 --no-locale \
		>"$DIR/initdb.log" 2>&1 ||
		{ tail -20 "$DIR/initdb.log" >&2; die "initdb failed (log: $DIR/initdb.log)"; }
	cat >>"$DATA/postgresql.conf" <<-EOF
		# test/harness/postgres.sh: a disposable server for tests.
		listen_addresses = '127.0.0.1'
		unix_socket_directories = ''
		fsync = off
		synchronous_commit = off
		full_page_writes = off
	EOF
	# The database of the end-to-end test, made in single-user mode, since
	# the binaries have no psql.
	echo "CREATE DATABASE shawke2e;" | "$bin/postgres" --single -D "$DATA" postgres >"$DIR/single.log" 2>&1 ||
		{ tail -20 "$DIR/single.log" >&2; die "could not create the database shawke2e"; }
	touch "$DIR/initialized"
}

up() {
	local bin port tries
	[[ "$(id -u)" != 0 ]] || die "initdb refuses to run as root: run test/harness/postgres.sh as a user"
	bin="$(binaries)"
	if running; then
		env_lines
		return
	fi
	init "$bin"
	# The port of the last run if it is free, else another. Another workspace
	# may take it between the check and the start: then the next one.
	port=""
	[[ -f "$DIR/port" ]] && ! listening "$(cat "$DIR/port")" && port="$(cat "$DIR/port")"
	for ((tries = 0; tries < 5; tries++)); do
		[[ -n "$port" ]] || port="$(free_port)"
		echo "$port" >"$DIR/port"
		: >"$DIR/server.log"
		if "$bin/pg_ctl" -D "$DATA" -l "$DIR/server.log" -w -t 60 -o "-p $port" start >/dev/null; then
			log "PostgreSQL $VERSION listens on 127.0.0.1:$port (data: $DATA)"
			env_lines
			return
		fi
		if grep -q 'could not create shared memory segment: Operation not permitted' "$DIR/server.log"; then
			die "PostgreSQL cannot create shared memory here; in the sandbox of an agent on macOS, run it outside the sandbox"
		fi
		grep -q 'Address already in use' "$DIR/server.log" || break
		port=""
	done
	rm -f "$DIR/port"
	tail -20 "$DIR/server.log" >&2
	die "PostgreSQL did not start (log: $DIR/server.log)"
}

stop() {
	if running; then
		"$(binaries)/pg_ctl" -D "$DATA" -m fast -w stop >/dev/null
	fi
}

down() {
	stop
	rm -rf "$DIR"
	log "PostgreSQL stopped and its data deleted"
}

case "${1:-}" in
up) up ;;
env) running || die "PostgreSQL is not running: run test/harness/postgres.sh up"; env_lines ;;
run)
	shift
	(($# > 0)) || die "usage: postgres.sh run CMD [ARG...]"
	running || die "PostgreSQL is not running: run test/harness/postgres.sh up"
	eval "$(env_lines)"
	exec "$@"
	;;
status)
	if running; then
		echo "running on 127.0.0.1:$(port), data in $DATA"
	else
		echo "not running"
		exit 3
	fi
	;;
stop) stop ;;
down) down ;;
*)
	echo "usage: postgres.sh up|env|run CMD...|status|stop|down" >&2
	exit 2
	;;
esac
