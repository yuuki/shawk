#!/bin/sh
# Creates the system user of the collector before the package installs it.
set -e
if ! getent group shawk-collector >/dev/null; then
	groupadd --system shawk-collector
fi
if ! getent passwd shawk-collector >/dev/null; then
	useradd --system --gid shawk-collector --no-create-home --home-dir /nonexistent \
		--shell /usr/sbin/nologin --comment "shawk collector" shawk-collector
fi
