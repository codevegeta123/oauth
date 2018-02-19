CREATE TABLE IF NOT EXISTS oauth_approvals (
  user_id VARCHAR(255),
  client_id VARCHAR(255),
  scope VARCHAR(255),
  status VARCHAR(10),
  expires_at TIMESTAMP NULL DEFAULT NULL,
  last_modified_at TIMESTAMP NULL DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS oauth_code (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(255),
  authentication LONG VARBINARY
);

CREATE TABLE IF NOT EXISTS oauth_access_token (
  token_id VARCHAR(255),
  token LONG VARBINARY,
  authentication_id VARCHAR(255) PRIMARY KEY,
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication LONG VARBINARY,
  refresh_token VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_id VARCHAR(255),
  token LONG VARBINARY,
  authentication LONG VARBINARY
);

CREATE TABLE IF NOT EXISTS oauth_client_token (
  token_id VARCHAR(255),
  token LONG VARBINARY,
  authentication_id VARCHAR(255) PRIMARY KEY,
  user_name VARCHAR(255),
  client_id VARCHAR(255)
);


CREATE TABLE IF NOT EXISTS oauth_client_details (
  client_id VARCHAR(255) PRIMARY KEY,
  resource_ids VARCHAR(255),
  client_secret VARCHAR(255),
  scope VARCHAR(255),
  authorized_grant_types VARCHAR(255),
  web_server_redirect_uri VARCHAR(255),
  authorities VARCHAR(255),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(255)
);



