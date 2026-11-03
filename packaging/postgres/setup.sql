-- Roles and database of shawk. Run as a superuser with psql, in a
-- terminal: psql asks for the password of each role.
--
--   psql -v ON_ERROR_STOP=1 -f setup.sql
--
-- Then apply the schema as shawk_owner and grant access:
--
--   shawk-migrate -dsn 'postgres://shawk_owner@db/shawk?sslmode=verify-full'
--   psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f grants.sql

-- Owns the schemas shawk and shawk_v1; runs shawk-migrate.
CREATE ROLE shawk_owner LOGIN;
-- The shawk connector: writes the tables of shawk, reads shawk_v1.
CREATE ROLE shawk_connector LOGIN;
-- Grafana: reads shawk_v1 only.
CREATE ROLE shawk_grafana LOGIN;

-- Grafana reads only, with a time limit. Only a superuser (or a role with
-- CREATEROLE and ADMIN on shawk_grafana) may set these, so they are here.
ALTER ROLE shawk_grafana SET default_transaction_read_only = on;
ALTER ROLE shawk_grafana SET statement_timeout = '30s';

CREATE DATABASE shawk OWNER shawk_owner;

-- The passwords. The roles above have none, and cannot log in with a
-- password until they do. psql asks for each password twice and sends it
-- hashed, so that it is in neither this file, the command line nor the
-- server log. An empty password leaves the role without one. If psql stops
-- here, set the passwords left with \password ROLE in psql.
\password shawk_owner
\password shawk_connector
\password shawk_grafana
