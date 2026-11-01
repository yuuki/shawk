-- Privileges of the roles of shawk. Run in the database shawk as its owner
-- (shawk_owner) after shawk-migrate, and again after a migration adds
-- tables or views:
--
--   psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f grants.sql

REVOKE ALL ON SCHEMA shawk, shawk_v1 FROM PUBLIC;

-- The connector upserts the tables, deletes rows older than its retention
-- and reads the views that name peers.
GRANT USAGE ON SCHEMA shawk, shawk_v1 TO shawk_connector;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shawk TO shawk_connector;
-- The history of migrations belongs to shawk-migrate.
REVOKE ALL ON shawk.schema_migrations FROM shawk_connector;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA shawk TO shawk_connector;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_connector;

-- Grafana reads the contract only (setup.sql makes it read-only with a
-- time limit).
GRANT USAGE ON SCHEMA shawk_v1 TO shawk_grafana;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_grafana;
