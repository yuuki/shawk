#!/usr/bin/env bash
# Installs Debian packages with sudo on a runner of CI:
#
#   scripts/apt-install.sh PACKAGE...
#
# The package mirrors of the runners are slow at times, for up to half an
# hour. Each run of apt-get has a time limit of its own (APT_TIMEOUT
# seconds, 90 by default), and a download that stalls fails and is tried
# again, so that a slow mirror costs minutes rather than the time of the
# tests. The install tries the package lists of the runner image first:
# apt-get update, which also reads the other repositories of the image,
# runs only after an install failed, as when the lists are older than the
# mirror. Packages downloaded before a time limit are kept for the next
# attempt.
#
# The sources of the runner image name a list of mirrors rather than a
# mirror (mirror+file:/etc/apt/apt-mirrors.txt): the mirror of the cloud of
# the runner (azure.archive.ubuntu.com, us-east-2.ec2.archive.ubuntu.com)
# first, then archive.ubuntu.com and security.ubuntu.com. apt starts every
# download at the first mirror, and moves it to the next one only after
# Acquire::Retries + 1 timeouts or other transient failures, which a slow
# mirror seldom reaches within the time limit. After a failed install, the
# first mirror of the list therefore becomes its last, so that the apt-get
# update and the install of the next attempt use another one.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: apt-install.sh PACKAGE..." >&2
	exit 2
fi
limit="${APT_TIMEOUT:-90}"
apt_get() {
	sudo timeout "$limit" apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 \
		-o Acquire::https::Timeout=30 "$@"
}

# apt tries the mirrors of the list in the order of their priority: tags,
# the lowest number first, the mirrors without one last. next_mirror gives
# the mirror tried first the largest number of the list plus one. apt tries
# the mirrors of a list without priorities in a random order: it stays as
# it is. APT_MIRRORS names another list, for the tests.
mirrors="${APT_MIRRORS:-/etc/apt/apt-mirrors.txt}"
next_mirror() {
	[[ -s $mirrors ]] || return 0
	local list
	list=$(awk '
		{ line[NR] = $0 }
		!/^#/ && match($0, /[ \t]priority:[0-9]+/) {
			p = substr($0, RSTART + 10, RLENGTH - 10) + 0
			if (!first || p < low) { first = NR; low = p; at = RSTART; len = RLENGTH }
			if (p > high) high = p
		}
		END {
			if (first)
				line[first] = substr(line[first], 1, at) "priority:" (high + 1) substr(line[first], at + len)
			for (i = 1; i <= NR; i++) print line[i]
		}' "$mirrors")
	printf '%s\n' "$list" | sudo tee "$mirrors" >/dev/null
}

attempts=3
for ((attempt = 1; ; attempt++)); do
	if apt_get install -y "$@"; then
		exit 0
	fi
	if ((attempt == attempts)); then
		echo "could not install $* in $attempts attempts" >&2
		exit 1
	fi
	echo "apt-get install failed (attempt $attempt of $attempts); updating the package lists from the next mirror" >&2
	# An install stopped by its time limit may leave dpkg interrupted.
	sudo timeout "$limit" dpkg --configure -a || true
	next_mirror || true
	apt_get update || true
done
