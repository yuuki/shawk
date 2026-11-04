-- Privileges of the roles of shawk. Run in the database shawk as its owner
-- (shawk_owner) after shawk-migrate, and again whenever shawk-migrate
-- applies new migrations:
--
--   psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f grants.sql

REVOKE ALL ON SCHEMA shawk, shawk_v1 FROM PUBLIC;
-- Only the owner creates temporary tables, which every role may by
-- default; setup.sql revokes the other objects.
DO $$ BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END $$;

-- The connector upserts the tables, deletes rows older than its retention
-- and reads the views that name peers.
GRANT USAGE ON SCHEMA shawk, shawk_v1 TO shawk_connector;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shawk TO shawk_connector;
-- The history of migrations belongs to shawk-migrate.
REVOKE ALL ON shawk.schema_migrations FROM shawk_connector;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA shawk TO shawk_connector;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_connector;

-- Grafana reads the contract only. These grants are what hold: the
-- read-only transactions and the time limit of setup.sql are defaults that
-- a session can change.
GRANT USAGE ON SCHEMA shawk_v1 TO shawk_grafana;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_grafana;

-- The users of the processes of Slurm jobs (job_users of the connector)
-- with their executables, peers and times tell the activity of the jobs of
-- other users, so shawk_v1.job_edges is for administrators: the owner reads
-- it, and may grant it to a role of administrators. Neither the connector
-- nor Grafana reads it; every viewer of Grafana could through the data
-- source.
DO $$ BEGIN
  IF to_regclass('shawk_v1.job_edges') IS NOT NULL THEN
    REVOKE ALL ON shawk_v1.job_edges FROM shawk_connector, shawk_grafana;
  END IF;
END $$;

-- Tables and views of later migrations, which shawk-migrate creates as the
-- owner, get the same privileges; run this file again after new
-- migrations all the same, for the objects they do not create themselves.
ALTER DEFAULT PRIVILEGES IN SCHEMA shawk GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO shawk_connector;
ALTER DEFAULT PRIVILEGES IN SCHEMA shawk GRANT USAGE ON SEQUENCES TO shawk_connector;
ALTER DEFAULT PRIVILEGES IN SCHEMA shawk_v1 GRANT SELECT ON TABLES TO shawk_connector, shawk_grafana;
