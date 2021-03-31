create table clients
(
    client_id           varchar(64) primary key not null,
    enabled             boolean      default true                 not null,
    client_secret       varchar(4096)                             not null,
    scopes              varchar(256)                              not null,
    auth_grant_types    varchar(256) default 'authorization_code' not null,
    client_auth_methods varchar(256) default 'basic'              not null,
    redirect_uris       varchar(4096)                             not null,
    atoken_ttl          integer      default 300000               not null,
    rtoken_ttl          integer      default 600000               not null,
    rtoken_reuse        boolean      default true                 not null,
    require_pkce        boolean      default false                not null,
    require_consent     boolean      default false                not null
);
