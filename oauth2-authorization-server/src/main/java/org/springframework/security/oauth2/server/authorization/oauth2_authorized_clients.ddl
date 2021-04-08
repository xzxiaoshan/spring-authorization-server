CREATE TABLE `oauth2_authorized_client`
(
    `client_registration_id`        varchar(100)  NOT NULL,
    `principal_name`                varchar(200)  NOT NULL,
    `authorization_code`            varchar(255)  NULL     DEFAULT NULL,
    `authorization_code_issued_at`  datetime(0)   NULL     DEFAULT NULL,
    `authorization_code_expires_at` datetime(0)   NULL     DEFAULT NULL,
    `authorized_grant_types`        varchar(100)  NULL     DEFAULT NULL,
    `access_token_type`             varchar(100)  NULL     DEFAULT NULL,
    `access_token_value`            blob          NULL,
    `access_token_issued_at`        datetime(0)   NULL     DEFAULT NULL,
    `access_token_expires_at`       datetime(0)   NULL     DEFAULT NULL,
    `access_token_scopes`           varchar(1000) NULL     DEFAULT NULL,
    `refresh_token_value`           blob          NULL,
    `refresh_token_issued_at`       datetime(0)   NULL     DEFAULT NULL,
    `refresh_token_expires_at`      datetime(0)   NULL     DEFAULT NULL,
    `created_at`                    datetime(0)   NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `additional_information`        blob          NULL,
    PRIMARY KEY (`client_registration_id`, `principal_name`) USING BTREE
)
