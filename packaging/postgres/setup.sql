-- Roles and database of shawk. Run as a superuser with psql, after
-- replacing the passwords:
--
--   psql -v ON_ERROR_STOP=1 -f setup.sql
--
-- Then apply the schema as shawk_owner and grant access:
--
--   shawk-migrate -dsn postgres://shawk_owner@db/shawk
--   psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f grants.sql

-- Owns the schemas shawk and shawk_v1; runs shawk-migrate.
CREATE ROLE shawk_owner LOGIN PASSWORD 'change-me';
-- The shawk connector: writes the tables of shawk, reads shawk_v1.
CREATE ROLE shawk_connector LOGIN PASSWORD 'change-me';
-- Grafana: reads shawk_v1 only.
CREATE ROLE shawk_grafana LOGIN PASSWORD 'change-me';

-- Defaults of the sessions of Grafana: read-only transactions and a time
-- limit on statements, against a runaway query of a dashboard. They are
-- not limits: a session can change them (SET statement_timeout = 0, BEGIN
-- READ WRITE), and every viewer of Grafana can send SQL of their own
-- through the data source. What holds are the privileges of grants.sql and
-- the revocations below. Only a superuser (or a role with CREATEROLE and
-- ADMIN on shawk_grafana) may set these, so they are here.
ALTER ROLE shawk_grafana SET default_transaction_read_only = on;
ALTER ROLE shawk_grafana SET statement_timeout = '30s';

CREATE DATABASE shawk OWNER shawk_owner;

-- The rest runs in the database shawk: no role but its owner may create
-- objects there. PostgreSQL 14 lets every role create tables and functions
-- in the schema public (15 and later do not), and every version lets every
-- role create large objects. The schema public of PostgreSQL 14 and the
-- functions of large objects belong to the superuser, so only a superuser
-- can revoke them. grants.sql revokes the temporary tables.
\connect shawk
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_creat(integer), lo_create(oid), lo_from_bytea(oid, bytea) FROM PUBLIC;
