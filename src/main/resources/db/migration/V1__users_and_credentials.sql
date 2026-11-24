-- Users (OAuth2 clients) and their credentials. Their client secrets are in
-- Keycloak; a credential's password is only kept as a hash.
create table dss_user (
    client_id   text primary key check (client_id ~ '^[a-z0-9][a-z0-9-]{2,40}$'),
    customer    text        not null,
    environment text        not null check (environment in ('local', 'dev', 'stg', 'pro')),
    description text        not null default '',
    active      boolean     not null default true,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

create table dss_credential (
    id                       text primary key check (id ~ '^[a-z0-9][a-z0-9-]{2,60}$'),
    client_id                text        not null references dss_user (client_id),
    status                   text        not null default 'pending' check (status in ('pending', 'active', 'revoked')),
    password_hash            text        not null,
    -- The password before the last rotation, accepted until then.
    previous_password_hash   text,
    previous_password_until  timestamptz,
    password_rotated_at      timestamptz not null default now(),
    created_at               timestamptz not null default now(),
    updated_at               timestamptz not null default now(),
    check ((previous_password_hash is null) = (previous_password_until is null))
);

create index dss_credential_client_id on dss_credential (client_id);
