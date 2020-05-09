# Quickstart

## 0. Requirements

- a Linux host (Ubuntu 18.04) for CMDB (the CMDB host)
- Linux hosts for tracing (the target hosts)

All of these hosts can be the same localhost.

## 1. Install PostgreSQL to the CMDB host

```shell
export PG_VERSION=11

wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo bash -c "echo 'deb http://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/pgdg.list"
sudo apt-get update
sudo apt-get install -y --no-install-recommends postgresql-${PG_VERSION} postgresql-client-${PG_VERSION} postgresql-contrib-${PG_VERSION}

PG_USER='shawk'
PG_PASSWD='shawk'
PG_DB='shawk'
sudo -u postgres psql -c "CREATE ROLE ${PG_USER} WITH LOGIN PASSWORD '${PG_PASSWD}';"
sudo -u postgres createdb --owner ${PG_USER} ${PG_DB} --echo
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${PG_DB} TO ${PG_USER};"
```

## 2. Install shawk to the CMDB host

```shell
export SHAWK_VERSION=0.7.0
mkdir -p /tmp/shawk; cd /tmp/shawk
wget -O - https://github.com/yuuki/shawk/releases/download/v${SHAWK_VERSION}/shawk_v${SHAWK_VERSION}_linux_amd64.tar.gz | tar xvzf -
SHAWK_CMDB_URL=postgres://shawk:shawk@localhost:5432/shawk?sslmode=disable ./shawk create-scheme
```

## 3. Deploy shawk to the target hosts

Run the following commands on each target host.

```shell

export SHAWK_VERSION=0.7.0
mkdir -p /tmp/shawk; cd /tmp/shawk
wget -O - https://github.com/yuuki/shawk/releases/download/v${SHAWK_VERSION}/shawk_v${SHAWK_VERSION}_linux_amd64.tar.gz | tar xvzf -

sudo su -
cd /tmp/shawk

export CMDB_HOST=127.0.0.1
SHAWK_CMDB_URL=postgres://shawk:shawk@${CMDB_HOST}:5432/shawk?sslmode=disable SHAWK_PROBE_MODE=polling SHAWK_PROBE_INTERVAL=1s SHAWK_FLUSH_INTERVAL=10s SHAWK_DEBUG=1 ./shawk probe
```

## 4. Using the `shawk look` on the CMDB host

```shell
cd /tmp/shawk
export TARGET_HOST="<Input your target IPv4 address>"
export SHAWK_CMDB_URL=postgres://shawk:shawk@127.0.0.1:5432/shawk?sslmode=disable
shawk look --ipv4 ${TARGET_HOST}
```
