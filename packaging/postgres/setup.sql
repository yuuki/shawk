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

-- Grafana reads only, with a time limit. Only a superuser (or a role with
-- CREATEROLE and ADMIN on shawk_grafana) may set these, so they are here.
ALTER ROLE shawk_grafana SET default_transaction_read_only = on;
ALTER ROLE shawk_grafana SET statement_timeout = '30s';

CREATE DATABASE shawk OWNER shawk_owner;
