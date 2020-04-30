#!/bin/sh

echo 'Tests - Enabling query log'

cat << EOF >> /var/lib/postgresql/data/postgresql.conf
log_destination = 'stderr'
log_statement = 'all'
EOF

kill -HUP 1
