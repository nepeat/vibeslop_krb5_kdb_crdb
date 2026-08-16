-- schema.sql variant for the single-region sea1 scale-test cluster.
-- Same tables as ../schema.sql, but one region (nodes run with
-- --locality=region=sea1) and no SURVIVE REGION FAILURE (needs >= 3
-- regions). GLOBAL tables keep the prod shape; with one region they
-- behave like fast follower-read tables.

CREATE DATABASE IF NOT EXISTS krb5
    PRIMARY REGION "sea1";

USE krb5;

CREATE TABLE IF NOT EXISTS principals (
    name        STRING      NOT NULL PRIMARY KEY,
    entry       BYTES       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

CREATE TABLE IF NOT EXISTS policies (
    name        STRING      NOT NULL PRIMARY KEY,
    entry       BYTES       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

CREATE TABLE IF NOT EXISTS aliases (
    alias       STRING      NOT NULL PRIMARY KEY,
    canonical   STRING      NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
) LOCALITY GLOBAL;

CREATE USER IF NOT EXISTS krb5kdc;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE principals, policies TO krb5kdc;
GRANT SELECT ON TABLE aliases TO krb5kdc;
