CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

ALTER TABLE issuers ADD COLUMN id uuid NOT NULL DEFAULT uuid_generate_v4();
ALTER TABLE issuers ADD COLUMN created_at timestamp NOT NULL DEFAULT NOW();
ALTER TABLE issuers ADD COLUMN expires_at timestamp;
ALTER TABLE issuers ADD COLUMN rotated_at timestamp;
ALTER TABLE issuers ADD COLUMN retired_at timestamp;
ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
ALTER TABLE issuers ADD PRIMARY KEY (id);

CREATE TABLE new_redemptions (
    id text NOT NULL,
    issuer_id uuid NOT NULL REFERENCES issuers(id),
    ts timestamp NOT NULL,
    payload text,
    UNIQUE(id, issuer_id)
) PARTITION BY LIST (issuer_id);

CREATE TABLE redemptions_default PARTITION OF new_redemptions DEFAULT;

INSERT INTO new_redemptions (id, issuer_id, ts, payload)
(
    SELECT redemptions.id, issuers.id, ts, payload
    FROM redemptions 
    JOIN issuers using(issuer_type)
);

DROP TABLE redemptions;

ALTER TABLE new_redemptions RENAME TO redemptions;
