-- Privileges of the roles of shawk. Run in the database shawk as its owner
-- (shawk_owner) after shawk-migrate, and again after a migration adds
-- tables or views:
--
--   psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f grants.sql

REVOKE ALL ON SCHEMA shawk, shawk_v1 FROM PUBLIC;

-- The connector upserts the tables and reads the views that name peers.
GRANT USAGE ON SCHEMA shawk, shawk_v1 TO shawk_connector;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA shawk TO shawk_connector;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA shawk TO shawk_connector;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_connector;

-- Grafana reads the contract only, read-only and with a time limit.
GRANT USAGE ON SCHEMA shawk_v1 TO shawk_grafana;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_grafana;
ALTER ROLE shawk_grafana SET default_transaction_read_only = on;
ALTER ROLE shawk_grafana SET statement_timeout = '30s';
