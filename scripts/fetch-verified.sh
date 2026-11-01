#!/usr/bin/env bash
# Downloads a file once to build/kernel/ and prints its path. The file is
# checked against its SHA-256 before every use, and downloaded again when it
# does not match.
#
#   scripts/fetch-verified.sh URL SHA256
#
# Requires curl and sha256sum.
set -euo pipefail

url="${1:?usage: fetch-verified.sh URL SHA256}"
sha256="${2:?usage: fetch-verified.sh URL SHA256}"

cache="$(cd "$(dirname "$0")/.." && pwd)/build/kernel"
file="$cache/$(basename "$url")"
verified() { echo "$sha256  $1" | sha256sum --check --status -; }

if [[ -f "$file" ]] && ! verified "$file"; then
	echo "$file does not match its SHA-256; downloading it again" >&2
	rm -f "$file"
fi
if [[ ! -f "$file" ]]; then
	mkdir -p "$cache"
	# A download of its own, renamed into the cache once verified, so that
	# concurrent runs neither clash nor see a partial file.
	part="$(mktemp "$cache/.download.XXXXXX")"
	trap 'rm -f "$part"' EXIT
	curl -fsSL --retry 3 -o "$part" "$url"
	if ! verified "$part"; then
		echo "$url does not match the SHA-256 $sha256" >&2
		exit 1
	fi
	chmod 0644 "$part"
	mv -f "$part" "$file"
fi
echo "$file"
