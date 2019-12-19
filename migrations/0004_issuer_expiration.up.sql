CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

ALTER TABLE issuers ADD COLUMN id uuid NOT NULL DEFAULT uuid_generate_v4();
ALTER TABLE issuers ADD COLUMN created_at timestamp NOT NULL DEFAULT NOW();
ALTER TABLE issuers ADD COLUMN expires_at timestamp;
ALTER TABLE issuers ADD COLUMN rotated_at timestamp;
ALTER TABLE issuers ADD COLUMN retired_at timestamp;
ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
ALTER TABLE issuers ADD PRIMARY KEY (id);
ALTER TABLE issuers ADD COLUMN version integer;

UPDATE issuers SET version = 1;

CREATE TABLE redemptions_v2 (
    id text NOT NULL,
    issuer_id uuid NOT NULL REFERENCES issuers(id),
    ts timestamp NOT NULL,
    payload text,
    UNIQUE(id, issuer_id)
) PARTITION BY LIST (issuer_id);

CREATE TABLE redemptions_v2_default PARTITION OF redemptions_v2 DEFAULT;
