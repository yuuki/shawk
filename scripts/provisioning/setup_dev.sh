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

echo 'Completed to setup'
