CREATE TABLE new_redemptions (
    id text NOT NULL PRIMARY KEY,
    issuer_type text NOT NULL,
    ts timestamp NOT NULL,
    payload text
);

INSERT INTO new_redemptions (id, issuer_type, ts, payload)
(
    SELECT redemptions.id, issuers.issuer_type, ts, payload
    FROM redemptions 
    JOIN issuers
    on redemptions.issuer_id = issuers.id
);

DROP TABLE redemptions;

ALTER TABLE new_redemptions RENAME TO redemptions;
ALTER TABLE redemptions RENAME CONSTRAINT new_redemptions_pkey TO redemptions_pkey;

ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
ALTER TABLE issuers ADD PRIMARY KEY (issuer_type);
ALTER TABLE issuers DROP COLUMN id;
ALTER TABLE issuers DROP COLUMN created_at;
ALTER TABLE issuers DROP COLUMN expires_at;
ALTER TABLE issuers DROP COLUMN rotated_at;
ALTER TABLE issuers DROP COLUMN retired_at;