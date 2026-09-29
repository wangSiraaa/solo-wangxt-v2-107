INSERT INTO tenants (id, name) VALUES
  ('tenant-a', 'Tenant A'),
  ('tenant-b', 'Tenant B'),
  ('tenant-c', 'Tenant C')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO oidc_issuers (issuer, display_name) VALUES
  ('http://localhost:8081/realms/tenant-a', 'Keycloak Tenant A'),
  ('http://localhost:8081/realms/tenant-b', 'Tenant B Realm'),
  ('http://localhost:8081/realms/tenant-c', 'Tenant C Realm')
ON CONFLICT (issuer) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO oidc_clients (tenant_id, issuer, client_id, client_secret, redirect_uris, enabled) VALUES
  ('tenant-a', 'http://localhost:8081/realms/tenant-a', 'multitenant-app', '',
   ARRAY['http://localhost:8080/callback/login', 'http://localhost:8080/callback/link'], true),
  ('tenant-b', 'http://localhost:8081/realms/tenant-b', 'multitenant-app', '',
   ARRAY['http://localhost:8080/callback/login', 'http://localhost:8080/callback/link'], true),
  ('tenant-a', 'http://localhost:8081/realms/tenant-c', 'multitenant-app', '',
   ARRAY['http://localhost:8080/callback/login'], false)
ON CONFLICT (tenant_id, issuer) DO UPDATE SET
  client_id = EXCLUDED.client_id,
  client_secret = EXCLUDED.client_secret,
  redirect_uris = EXCLUDED.redirect_uris,
  enabled = EXCLUDED.enabled;
