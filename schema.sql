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

-- ---------------------------------------------------------------------------
-- kprop/iprop replica mode (opt-in; see README "Running as a kprop/iprop
-- replica"). A full `kdb5_util load` — what kpropd runs on every full
-- propagation — streams the PRIMARY's entire realm into the staging tables
-- below, then promote_db diff-syncs them into the live tables. Three
-- independent keys must all be present for the plugin to accept it:
--   1. `prop_receiver = kprop|iprop` in the receiver host's [dbmodules],
--   2. the prop_control marker row (operator SQL, below),
--   3. the krb5prop SQL identity — the only user with staging-table DML.
-- While the marker is enabled, the plugin REFUSES kadmind/kdb5_util writes
-- to the live tables from everyone except the receiver: a replica realm is
-- read-only outside the propagation stream, and local writes would be
-- silently destroyed by the next full resync anyway.

-- Staging: REGIONAL, not GLOBAL — nothing reads these until promote, so
-- paying the GLOBAL commit-wait per dump record would be pure waste. Lands
-- in the primary region by default; ALTER ... SET LOCALITY REGIONAL BY
-- TABLE IN "<region>" to move it next to the receiver host.
CREATE TABLE IF NOT EXISTS principals_staging (
    name        STRING      NOT NULL PRIMARY KEY,
    entry       BYTES       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY REGIONAL BY TABLE;

CREATE TABLE IF NOT EXISTS policies_staging (
    name        STRING      NOT NULL PRIMARY KEY,
    entry       BYTES       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY REGIONAL BY TABLE;

-- Replica-mode marker + receiver lease. The plugin never INSERTs here:
-- creating the row is the operator's explicit opt-in —
--   enable:  UPSERT INTO prop_control (singleton, enabled, mode)
--            VALUES (true, true, 'iprop');
--   disable (promote-to-primary): UPDATE prop_control SET enabled = false;
-- mode 'iprop' also permits plain kprop loads; 'kprop' permits only those.
-- The lease makes "exactly one receiver" structural: open(temporary) takes
-- it, promote_db verifies and releases it, a second kpropd is refused.
CREATE TABLE IF NOT EXISTS prop_control (
    singleton       BOOL        NOT NULL PRIMARY KEY DEFAULT true
                                CHECK (singleton),
    enabled         BOOL        NOT NULL,
    mode            STRING      NOT NULL CHECK (mode IN ('kprop', 'iprop')),
    lease_holder    STRING,
    lease_expires   TIMESTAMPTZ,
    last_promote_at TIMESTAMPTZ
) LOCALITY GLOBAL;

-- Least-privilege role for the KDC/kadmind:
CREATE USER IF NOT EXISTS krb5kdc;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE principals, policies TO krb5kdc;
GRANT SELECT ON TABLE aliases TO krb5kdc;  -- read-only: aliases are operator SQL
GRANT SELECT ON TABLE prop_control TO krb5kdc;  -- write-freeze check only

-- The replica-receiver identity (kpropd host ONLY). Deliberately powerful —
-- it can rewrite the whole realm; that is what receiving a kprop dump IS.
-- Provision its client cert solely on the receiver host. It can extend or
-- release the lease (UPDATE) but cannot create the marker row (no INSERT):
-- enabling replica mode stays an operator act.
CREATE USER IF NOT EXISTS krb5prop;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE principals, policies,
    principals_staging, policies_staging TO krb5prop;
GRANT SELECT, UPDATE ON TABLE prop_control TO krb5prop;
