create table oauth2_registered_client
(
    client_id varchar_ignorecase(64) primary key not null,
    enabled             boolean      default true                 not null,
    client_secret       varchar(4096)                             not null,
    scopes              varchar(256)                              not null,
    auth_grant_types    varchar(256) default 'authorization_code' not null,
    client_auth_methods varchar(256) default 'basic'              not null,
    redirect_uris       varchar(4096)                             not null,
    access_token_ttl    integer      default 300000               not null,
    refresh_token_ttl   integer      default 600000               not null,
    refresh_token_reuse boolean      default true                 not null,
    require_pkce        boolean      default false                not null,
    require_consent     boolean      default false                not null
);
