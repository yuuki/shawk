-- The users of the processes of Slurm jobs, which the connector keeps with
-- job_users from agents run with -job-users.
--
-- The user id of a process of a job (process.user.id) is part of its
-- identity, so that the jobs of different users with the same unit, comm
-- and service have rows of their own: rows grow with users, not with jobs.
-- user_id is NULL for other processes, and for processes of jobs whose user
-- is unknown: the agent could not read it, or did not send it, or the
-- connector did not keep it. The rows written before keep NULL, which is
-- what they are: processes whose user is unknown. Job ids are not kept.
--
-- PostgreSQL 14 has no NULLS NOT DISTINCT, so the identity is a unique
-- index on coalesce(user_id, -1), which the connector names in ON CONFLICT.
-- Connectors from before this migration upsert processes on the former
-- unique key, which no longer exists; their writes fail and wait until they
-- are upgraded.
ALTER TABLE shawk.processes ADD COLUMN user_id bigint CHECK (user_id BETWEEN 0 AND 4294967295);
ALTER TABLE shawk.processes DROP CONSTRAINT processes_host_id_unit_comm_service_name_key;
CREATE UNIQUE INDEX processes_identity ON shawk.processes (host_id, unit, comm, service_name, coalesce(user_id, -1));

-- The edges of the processes of Slurm jobs with their users: which users
-- connected to what, from which host and executable, and when. user_id is
-- NULL where the user is unknown. The sockets of kernel clients (NFS,
-- Lustre) belong to the kernel, not to a job, so their users are not known.
--
-- User ids with executables, peers and times tell the activity of the jobs
-- of other users, so the view is for administrators: grants.sql keeps it
-- from the connector and Grafana, which read the rest of shawk_v1, and the
-- grants that default privileges gave other roles as it was created are
-- revoked here, so that only its owner reads it until then.
CREATE VIEW shawk_v1.job_edges AS
SELECT h.hostname AS host, e.host_id, p.unit, p.service_name AS service, p.exe, p.user_id,
       e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns, e.first_seen, e.last_seen
FROM shawk.edges e
JOIN shawk.processes p ON p.id = e.process_id
JOIN shawk.hosts h ON h.id = e.host_id
WHERE p.unit LIKE 'slurm/%';

DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT a.grantee
    FROM pg_class c, aclexplode(c.relacl) a
    WHERE c.oid = 'shawk_v1.job_edges'::regclass AND a.grantee <> c.relowner
  LOOP
    IF r.grantee = 0 THEN
      REVOKE ALL ON shawk_v1.job_edges FROM PUBLIC;
    ELSE
      EXECUTE format('REVOKE ALL ON shawk_v1.job_edges FROM %I', pg_get_userbyid(r.grantee));
    END IF;
  END LOOP;
END
$$;
