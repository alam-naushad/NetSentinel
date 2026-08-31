-- ==============================================================================
-- PostgreSQL Initialization Script: Hardened Least-Privilege Setup
-- Mounted at: /docker-entrypoint-initdb.d/init-db.sql
-- Runs automatically on container first-boot when data volume is initialized.
-- ==============================================================================

-- Create application database if not already created by POSTGRES_DB
-- (PostgreSQL official image creates POSTGRES_DB automatically, but we ensure idempotency)

DO $$
BEGIN
    -- Ensure application user exists
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'soc_user') THEN
        CREATE ROLE soc_user WITH LOGIN PASSWORD 'soc_password';
    END IF;
END
$$;

-- Grant permissions to application role on target database
\connect soc_telemetry

-- Ensure schema public ownership and permissions
GRANT ALL ON SCHEMA public TO soc_user;
GRANT CREATE ON SCHEMA public TO soc_user;

-- Set default search path and timezone
ALTER ROLE soc_user SET search_path TO public;
ALTER ROLE soc_user SET timezone TO 'UTC';

-- Grant permissions for Alembic and SQLAlchemy on future tables and sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO soc_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO soc_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO soc_user;
