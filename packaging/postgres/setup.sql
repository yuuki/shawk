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

CREATE DATABASE shawk OWNER shawk_owner;
