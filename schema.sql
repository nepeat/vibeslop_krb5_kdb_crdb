-- kdb-crdb schema — CockroachDB multi-region, strongly consistent
--
-- GLOBAL tables are the entire point of this design:
--   * reads: non-stale, strongly consistent, served in-region (no WAN hop)
--     -> every AS-REQ / TGS-REQ get_principal is a local read
--   * writes: commit "in the future" so all regions can serve them
--     consistently; costs a few hundred ms -> fine for kadmin/pw changes
--
-- Prereq: cluster nodes started with --locality=region=...,zone=...

CREATE DATABASE IF NOT EXISTS krb5
    PRIMARY REGION "us-west2"
    REGIONS "us-west2", "us-east1", "europe-west4"
    SURVIVE REGION FAILURE;

USE krb5;

CREATE TABLE IF NOT EXISTS principals (
    name        STRING      NOT NULL PRIMARY KEY,  -- canonical unparsed name, incl. realm
    entry       BYTES       NOT NULL,              -- versioned postcard blob (marshal.rs)
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

CREATE TABLE IF NOT EXISTS policies (
    name        STRING      NOT NULL PRIMARY KEY,
    entry       BYTES       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

-- Aliases: alternate principal names resolving to a canonical entry.
-- Managed by operator SQL (kadmin has no alias verbs, same as kldap where
-- aliases are edited through LDAP directly). An out-of-realm canonical name
-- is a referral: the plugin only follows it when the KDC passes
-- KRB5_KDB_FLAG_REFERRAL_OK (see lib.rs::get_principal).
CREATE TABLE IF NOT EXISTS aliases (
    alias       STRING      NOT NULL PRIMARY KEY,  -- unparsed name, incl. realm
    canonical   STRING      NOT NULL,              -- target principal name
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

-- If you ever DO need account lockout / last-auth tracking, do NOT write it
-- into the GLOBAL principals table (every login would become a cross-region
-- consensus write). Mirror klmdb's split-lockout design instead: a separate
-- REGIONAL BY ROW table with relaxed semantics, keyed per-KDC-region.
--
-- CREATE TABLE IF NOT EXISTS lockout (
--     name             STRING NOT NULL,
--     crdb_region      crdb_internal_region NOT NULL DEFAULT default_to_database_primary_region(gateway_region()),
--     last_success     INT8 NOT NULL DEFAULT 0,
--     last_failed      INT8 NOT NULL DEFAULT 0,
--     fail_auth_count  INT8 NOT NULL DEFAULT 0,
--     PRIMARY KEY (name)
-- ) LOCALITY REGIONAL BY ROW;

-- Least-privilege role for the KDC/kadmind:
CREATE USER IF NOT EXISTS krb5kdc;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE principals, policies TO krb5kdc;
GRANT SELECT ON TABLE aliases TO krb5kdc;  -- read-only: aliases are operator SQL
