insert into oauth2_registered_client (client_id,enabled,client_secret,scopes,redirect_uris)
values ('test',true,'secret','test','https://test'),
       ('test2',false,'test','test','https://test'),
       ('test4',true,'test','test','b0rkenUr1#fuj');

insert into oauth2_registered_client (client_id,enabled,client_secret,scopes,redirect_uris,auth_grant_types)
values ('test3',true,'test',' openid |  test ','https://test|https://test2','authorization_code|password')
