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

attempts=3
for ((attempt = 1; ; attempt++)); do
	if apt_get install -y "$@"; then
		exit 0
	fi
	if ((attempt == attempts)); then
		echo "could not install $* in $attempts attempts" >&2
		exit 1
	fi
	echo "apt-get install failed (attempt $attempt of $attempts); updating the package lists" >&2
	# An install stopped by its time limit may leave dpkg interrupted.
	sudo timeout "$limit" dpkg --configure -a || true
	apt_get update || true
done
