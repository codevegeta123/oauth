INSERT INTO oauth_client_details
(client_id, client_secret, scope, authorized_grant_types,
 web_server_redirect_uri, authorities, access_token_validity,
 refresh_token_validity, additional_information, autoapprove)
VALUES
  ('fooClientIdPassword', 'secret', 'foo,read,write',
   'password,authorization_code,refresh_token', null, 'ROLE_USER,ROLE_ADMIN', 36000, 36000, null, true);
INSERT INTO oauth_client_details
(client_id, client_secret, scope, authorized_grant_types,
 web_server_redirect_uri, authorities, access_token_validity,
 refresh_token_validity, additional_information, autoapprove)
VALUES
  ('sampleClientId', 'secret', 'read,write,foo,bar',
   'implicit', null, 'ROLE_USER,ROLE_ADMIN', 36000, 36000, null, false);
INSERT INTO oauth_client_details
(client_id, client_secret, scope, authorized_grant_types,
 web_server_redirect_uri, authorities, access_token_validity,
 refresh_token_validity, additional_information, autoapprove)
VALUES
  ('barClientIdPassword', 'secret', 'bar,read,write',
   'password,authorization_code,refresh_token', null, 'ROLE_USER,ROLE_ADMIN', 36000, 36000, null, true);

INSERT INTO user
(phone, email, enabled, name, password, username)
VALUES (987238381, 'rp1@gmail.com', 0, 'rohith', 'next123', 'rohith');

INSERT INTO user
(phone, email, enabled, name, password, username)
VALUES (9872383882, 'rp2@gmail.com', 0, 'admin', 'next123', 'admin');

INSERT INTO user
(phone, email, enabled, name, password, username)
VALUES (9872383883, 'rp3@gmail.com', 0, 'user', 'password', 'user');

INSERT INTO role (role) values ('ADMIN');
INSERT INTO role (role) values ('USER');

INSERT INTO user_role (user_id, role_id) values (1, 1);
INSERT INTO user_role (user_id, role_id) values (2, 1);
INSERT INTO user_role (user_id, role_id) values (3, 2);




