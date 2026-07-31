# `io.lumnus.dbeaver.auth.openbao` — OpenBao dynamic database credentials

A dbeaver-core **auth model** that issues a fresh, short-lived database credential from OpenBao on
every connect, scoped to the authenticated principal. Nothing is stored on the connection.

## Why it is a bundle and not a patch

`org.jkiss.dbeaver.dataSourceAuth` is a **public extension point** in dbeaver-core, and CloudBeaver
enumerates auth models from the core registry at runtime
(`DataSourceProviderRegistry.getApplicableAuthModels(driver)`) rather than carrying a hardcoded list.
So this bundle is purely **additive** — neither CloudBeaver nor dbeaver-core is modified.

That matters for three reasons beyond effort:

1. **It survives host version bumps.** Nothing to rebase; a CloudBeaver upgrade is routine.
2. **It is upstream-shaped.** Structurally the same move dbeaver's own `AuthModelPgPass` makes —
   resolve the password from an external source at connect time. A candidate to offer upstream
   rather than carry forever.
3. **It is edition-independent.** It works because the registry is open, not because a gate was
   defeated. (`secretManagerEnabled: false` gates an unrelated feature.)

## How identity reaches the connect path

CloudBeaver binds the authenticated web session into the datasource registry as its credentials
provider, and `WebSession` implements both interfaces the chain needs:

```
CloudBeaver   WebSessionProjectImpl.createRegistryWithCredentialsProvider()
                → dataSourceRegistry.setAuthCredentialsProvider(webSession)
dbeaver-core  DBPDataSourceRegistry.getAuthCredentialsProvider() → DBACredentialsProvider
closing       WebSession implements DBACredentialsProvider *and* SMCredentialsProvider
                → getActiveUserCredentials().getUserId()
```

**The model refuses to mint a credential when it cannot identify the caller.** An unattributable
credential is worse than a failed connection.

## Configuration

**Deployment level** (environment — properties of the deployment, not of any connection):

| Variable | Default | Purpose |
|---|---|---|
| `LUMNUS_OPENBAO_ADDR` | `https://vault.lab.lumnus.net:8200` | OpenBao API address |
| `LUMNUS_OPENBAO_CACERT` | — | PEM of the private CA. Avoids rebuilding the JVM truststore |
| `LUMNUS_OPENBAO_K8S_ROLE` | — | OpenBao Kubernetes auth role for the pod's ServiceAccount |
| `LUMNUS_OPENBAO_K8S_AUTH_PATH` | `kubernetes` | Mount path of the Kubernetes auth method |
| `LUMNUS_OPENBAO_TOKEN_FILE` | — | Out-of-cluster development fallback only |

The production path is **Kubernetes auth** — the pod exchanges its ServiceAccount JWT for a
short-lived OpenBao token. No static token is stored anywhere.

**Connection level** (auth properties):

| Property | Required | Purpose |
|---|---|---|
| `openbao.role` | yes | Database role to request, e.g. `substrate-ro` |
| `openbao.requiredPermission` | no | Coarse eligibility gate — see the limitation below |

## Known limitation — eligibility is NOT yet enforced OpenBao-side

Stated plainly because it would otherwise read as stronger than it is.

The CloudBeaver pod authenticates to OpenBao with **one** identity (its ServiceAccount). The
principal is resolved and sent as `X-Lumnus-Principal` for audit correlation, but OpenBao cannot
distinguish *which* end user is behind a request — so any authenticated CloudBeaver user can obtain
any role a connection is configured for. `openbao.requiredPermission` provides a coarse check
**inside the server's trust boundary** (real enforcement, since the user cannot tamper with the
server), but it is not defence in depth.

Closing this is the broker's job (`PENDING_ACCESS_BROKER` AB.2 / Cell 5): the broker authenticates
the end user, decides eligibility, and mints the credential itself — at which point OpenBao sees a
per-principal request and the enforcement moves outside CloudBeaver's trust boundary entirely.

**So: this bundle proves the mechanism and delivers real short-lived credentials. It is not the
authorization story.** Do not deploy it against a store where "any authenticated CloudBeaver user"
is an unacceptable audience until the broker lands.

## Build

Registered in `server/bundles/pom.xml` and `server/features/io.cloudbeaver.server.feature/feature.xml`.
The standard backend build picks it up:

```bash
./deploy/build-backend.sh      # clones dbeaver + dbeaver-common as siblings, then builds
```

## Verified against source

Every core API this bundle calls was checked against `dbeaver@devel` rather than assumed —
including that `mariaDB` is a *driver* id, not a datasource-provider id (MariaDB/Galera is served by
the `mysql` provider). Auth-model applicability is declared with provider ids only.
