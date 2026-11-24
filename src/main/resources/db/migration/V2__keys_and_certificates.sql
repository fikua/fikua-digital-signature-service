-- A credential's key: created here, kept encrypted and destroyed with the row.
-- Envelope encryption: a data key per credential, encrypted with the master key
-- kek_id, which is not in the database.
create table dss_credential_key (
    credential_id text primary key references dss_credential (id),
    kek_id        text        not null,
    encrypted_dek bytea       not null,
    dek_nonce     bytea       not null,
    encrypted_key bytea       not null,
    key_nonce     bytea       not null,
    public_key    bytea       not null,
    created_at    timestamptz not null default now()
);

-- The certificates of a credential, all for the same key; the last one is in use.
create table dss_credential_certificate (
    id            bigint generated always as identity primary key,
    credential_id text        not null references dss_credential (id),
    chain_pem     text        not null,
    not_after     timestamptz not null,
    installed_at  timestamptz not null default now()
);

create index dss_credential_certificate_credential on dss_credential_certificate (credential_id, id desc);
