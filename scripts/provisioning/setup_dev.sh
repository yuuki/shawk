#!/bin/bash

set -eux

sudo apt-get -yq update
sudo apt-get -yq install build-essential gcc make git

# Install Go
GOVER='1.14.1'
GOTAR="go${GOVER}.linux-amd64.tar.gz"

wget https://dl.google.com/go/${GOTAR}
sudo tar -C /usr/local -xzf ${GOTAR}
rm -f ${GOTAR}
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

mkdir -p /home/vagrant/go/src/github.com/yuuki/shawk/

# Install postgres
PG_VERSION=11

wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo bash -c "echo 'deb http://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/pgdg.list"
sudo apt-get -yq update
sudo apt-get install -yq postgresql-${PG_VERSION} postgresql-client-${PG_VERSION} postgresql-contrib-${PG_VERSION}
echo 'Completed to setup'
