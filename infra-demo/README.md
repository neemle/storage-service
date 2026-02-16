# External Auth Demo Stacks

These stacks preconfigure Keycloak for NSS external auth modes while keeping the same topology as the
root demo stack (master, delivery/backup/volume replicas, observability, and demo traffic).

## Stack Files

- `infra-demo/keycloak-oidc/docker-compose.yml`
- `infra-demo/keycloak-oauth2/docker-compose.yml`
- `infra-demo/keycloak-saml2/docker-compose.yml`

## Run

From repository root:

```bash
docker compose -f infra-demo/keycloak-oidc/docker-compose.yml up --build
```

Swap the file path to `keycloak-oauth2` or `keycloak-saml2` for those modes.

## Default Credentials

Keycloak:
- URL: `http://localhost:8080`
- Realm: `nss`
- Client: `nss-console`
- Users:
  - `admin` / `admin` (role `nss-admin`)
  - `user` / `user`

NSS UI:
- URL: `http://localhost:9001`
- Click `Continue with external identity`.

## Dockerized Verification

Run external auth tests for all three modes:

```bash
./scripts/external-auth-tests.sh
```
