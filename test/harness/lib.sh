# shellcheck shell=bash
# Helpers of the scripts of test/harness, which source this file.
#
# Everything a script starts belongs to the workspace, the checkout or
# worktree the script is in: its state is in build/harness of the workspace,
# and its names and ports are derived from the path of the workspace, so
# that worktrees and sessions running at the same time on one host do not
# clash. Downloads are pinned by version and SHA-256 and cached in
# SHAWK_CACHE_DIR (default build/cache of the workspace); several workspaces
# can share one, e.g. SHAWK_CACHE_DIR=~/.cache/shawk. The VM of slurm.sh,
# which mounts the workspace, keeps its own state in SHAWK_HARNESS_STATE.
set -euo pipefail

HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HARNESS/../.." && pwd)"
STATE="${SHAWK_HARNESS_STATE:-$ROOT/build/harness}"
CACHE="${SHAWK_CACHE_DIR:-$ROOT/build/cache}"

log() { echo "harness: $*" >&2; }
die() {
	echo "harness: $*" >&2
	exit 1
}

# sha256 [FILE]: the SHA-256 of FILE, or of the standard input.
sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$@" | cut -d' ' -f1
	else
		shasum -a 256 "$@" | cut -d' ' -f1
	fi
}

# The workspace: 8 hex digits of the SHA-256 of its path, or
# SHAWK_HARNESS_ID.
WS_ID="${SHAWK_HARNESS_ID:-$(printf %s "$ROOT" | sha256 | cut -c1-8)}"
[[ "$WS_ID" =~ ^[a-z0-9][a-z0-9-]{0,15}$ ]] || die "SHAWK_HARNESS_ID must be up to 16 lowercase letters, digits and dashes"

# fetch URL SHA256: downloads URL once to the cache and prints its path. The
# file is checked against SHA256 before every use and downloaded again when
# it does not match, as scripts/fetch-verified.sh does.
fetch() {
	local url=$1 sum=$2 dir file part
	dir="$CACHE/downloads"
	file="$dir/$(basename "$url")"
	if [[ -f "$file" && "$(sha256 "$file")" != "$sum" ]]; then
		log "$file does not match its SHA-256; downloading it again"
		rm -f "$file"
	fi
	if [[ ! -f "$file" ]]; then
		mkdir -p "$dir"
		# A download of its own, renamed into the cache once verified, so that
		# concurrent runs neither clash nor see a partial file.
		part="$(mktemp "$dir/.download.XXXXXX")"
		log "downloading $url"
		if ! curl -fsSL --retry 3 --connect-timeout 30 --max-time 1800 -o "$part" "$url"; then
			rm -f "$part"
			die "could not download $url"
		fi
		if [[ "$(sha256 "$part")" != "$sum" ]]; then
			rm -f "$part"
			die "$url does not match the SHA-256 $sum"
		fi
		chmod 0644 "$part"
		mv -f "$part" "$file"
	fi
	echo "$file"
}

# lock NAME: takes the lock NAME of the workspace, waiting for another run
# that holds it, until the script exits; a lock whose holder died is taken
# over. It serializes the commands that change an environment, which
# sessions sharing a workspace may run at once.
lock() {
	local dir="$STATE/$1.lock" pid i
	mkdir -p "$STATE"
	for ((i = 0; ; i++)); do
		if mkdir "$dir" 2>/dev/null; then
			echo $$ >"$dir/pid"
			# shellcheck disable=SC2064
			trap "rm -rf '$dir'" EXIT
			return
		fi
		pid="$(cat "$dir/pid" 2>/dev/null || true)"
		if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
			rm -rf "$dir"
			continue
		fi
		((i > 0)) || log "waiting for another run on this workspace ($dir)"
		((i < 3600)) || die "timed out waiting for $dir"
		sleep 1
	done
}

# listening PORT: whether a TCP socket listens on PORT of 127.0.0.1.
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# free_port: a port that nothing listens on, from a base that the workspace
# gives, so that a workspace mostly gets the same port. Below the ephemeral
# ports of Linux (32768) and macOS (49152).
free_port() {
	local port i
	port=$((21000 + 0x$(printf %s "$WS_ID" | sha256 | cut -c1-4) % 8000))
	for ((i = 0; i < 100; i++, port++)); do
		listening "$port" || {
			echo "$port"
			return
		}
	done
	die "no free port from $((port - 100)) to $port"
}

# platform: the operating system and architecture of the host, as
# darwin-arm64, darwin-amd64, linux-arm64 or linux-amd64.
platform() {
	local os arch
	case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) die "unsupported operating system $(uname -s)" ;;
	esac
	case "$(uname -m)" in
	arm64 | aarch64) arch=arm64 ;;
	x86_64 | amd64) arch=amd64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	echo "$os-$arch"
}
