/*
 * Lumnus substrate — OpenBao dynamic database credentials for DBeaver/CloudBeaver.
 * Licensed under the Apache License, Version 2.0 (same as the host project).
 */
package io.lumnus.dbeaver.auth.openbao;

import io.cloudbeaver.model.session.WebSession;
import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSource;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.access.DBACredentialsProvider;
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.jkiss.dbeaver.model.impl.auth.AuthModelDatabaseNative;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;

import java.util.Properties;

/**
 * Auth model that issues a <em>fresh, short-lived</em> database credential from OpenBao on every
 * connect — minted <b>on the authenticated user's own authority</b>, never the server's.
 *
 * <h2>Why it is a bundle and not a patch</h2>
 * {@code org.jkiss.dbeaver.dataSourceAuth} is a public extension point and CloudBeaver enumerates
 * auth models from the core registry at runtime, so this model is contributed rather than patched
 * in. It is structurally the same move dbeaver's own {@code AuthModelPgPass} makes: resolve the
 * password from an external source at connect time instead of from anything stored.
 *
 * <h2>Whose authority the credential is minted on</h2>
 * The connect path reaches the authenticated session because CloudBeaver binds it into the
 * datasource registry as the credentials provider
 * ({@code dataSourceRegistry.setAuthCredentialsProvider(webSession)}). From the session this model
 * takes the user's <em>federated OIDC access token</em> and exchanges it at OpenBao's JWT auth
 * method for a user-scoped OpenBao token. OpenBao then evaluates its own policies against that
 * user's identity and groups.
 *
 * <p>The consequence worth stating plainly: <b>OpenBao cannot issue a credential the user is not
 * entitled to</b>, because the request never carries anyone else's authority. Eligibility is not a
 * check this code performs and could get wrong — it is a property of who signed the request.
 *
 * <h2>Two refusals, both deliberate</h2>
 * <ol>
 *   <li><b>No identity, no credential.</b> An unattributable credential is worse than a failed
 *       connection. In a plain DBeaver desktop runtime the provider is not a {@code WebSession},
 *       so this fails closed by construction rather than by policy.</li>
 *   <li><b>{@link #saveCredentials} is a no-op.</b> The base class writes the resolved
 *       username/password back into the stored connection configuration — which for an ephemeral
 *       credential persists a secret that is dead within the hour and quietly reintroduces exactly
 *       the stored-password pattern this exists to remove. It would have looked like it worked.</li>
 * </ol>
 *
 * <h2>Idle tabs</h2>
 * The token is read from the session on every connect, and the session's copy is refreshed on every
 * HTTP request by the reverse proxy. So a tab left idle for hours still connects, as long as the
 * user's Keycloak session is alive. When it is not, the proxy bounces them to Keycloak — which is
 * the correct outcome rather than a silent failure.
 */
public class OpenBaoAuthModel extends AuthModelDatabaseNative<OpenBaoCredentials> {

    private static final Log log = Log.getLog(OpenBaoAuthModel.class);

    /** OpenBao database role to request, e.g. {@code substrate-ro}. Required. */
    public static final String PROP_ROLE = "openbao.role";

    private volatile OpenBaoClient client;

    @NotNull
    @Override
    public OpenBaoCredentials createCredentials() {
        return new OpenBaoCredentials();
    }

    @Override
    protected void loadCredentials(
        @NotNull DBPDataSourceContainer dataSource,
        @NotNull DBPConnectionConfiguration configuration,
        OpenBaoCredentials credentials
    ) {
        // Deliberately NOT calling super: nothing stored on the connection is used as a credential.
        try {
            String role = configuration.getAuthProperty(PROP_ROLE);
            if (role == null || role.isBlank()) {
                throw new DBException("Connection does not declare an OpenBao role. Set the '"
                    + PROP_ROLE + "' authentication property (e.g. 'substrate-ro').");
            }

            WebSession session = resolveSession(dataSource);
            String principal = resolvePrincipal(session);
            String userToken = session.getFederatedAccessToken();
            if (userToken == null || userToken.isBlank()) {
                throw new DBException("No federated access token is present for '" + principal
                    + "'. The credential must be minted on the user's own authority, so this "
                    + "connection cannot proceed. Check that the reverse proxy forwards the access "
                    + "token (oauth2-proxy: --set-xauthrequest --pass-access-token).");
            }
            credentials.setPrincipal(principal);

            OpenBaoClient.DynamicCredential issued =
                getClient().issueForUser(userToken, role, principal);
            credentials.setUserName(issued.username());
            credentials.setUserPassword(issued.password());
            credentials.setLeaseId(issued.leaseId());
            credentials.setResolutionError(null);
        } catch (Throwable e) {
            // Deferred to initAuthentication — loadCredentials also runs outside connect, and
            // throwing here surfaces failures far from the attempt that caused them.
            credentials.setResolutionError(e);
        }
    }

    @Override
    public Object initAuthentication(
        @NotNull DBRProgressMonitor monitor,
        @NotNull DBPDataSource dataSource,
        @NotNull OpenBaoCredentials credentials,
        @NotNull DBPConnectionConfiguration configuration,
        @NotNull Properties connectProps
    ) throws DBException {
        Throwable err = credentials.getResolutionError();
        if (err != null) {
            throw new DBCException("Could not obtain a short-lived credential from OpenBao: "
                + err.getMessage(), err);
        }
        log.debug("Connecting as OpenBao-issued user " + credentials.getUserName()
            + " for principal " + credentials.getPrincipal()
            + " (lease " + credentials.getLeaseId() + ")");
        return super.initAuthentication(monitor, dataSource, credentials, configuration, connectProps);
    }

    /** No-op by design — an ephemeral credential must never be persisted. See the class comment. */
    @Override
    public void saveCredentials(
        @NotNull DBPDataSourceContainer dataSource,
        @NotNull DBPConnectionConfiguration configuration,
        @NotNull OpenBaoCredentials credentials
    ) {
        // intentionally empty
    }

    /** Supplies the credential for <em>this</em> connect only; distinct from persistence. */
    @Override
    public void provideCredentials(
        @NotNull DBPDataSourceContainer dataSource,
        @NotNull DBPConnectionConfiguration configuration,
        @NotNull OpenBaoCredentials credentials
    ) {
        configuration.setUserName(credentials.getUserName());
        configuration.setUserPassword(credentials.getUserPassword());
    }

    // ── identity ──────────────────────────────────────────────────────────────────────────────

    private WebSession resolveSession(DBPDataSourceContainer dataSource) throws DBException {
        DBPDataSourceRegistry registry = dataSource.getRegistry();
        DBACredentialsProvider provider = registry == null ? null : registry.getAuthCredentialsProvider();
        if (!(provider instanceof WebSession session)) {
            throw new DBException("No authenticated web session is bound to this connection, so a "
                + "credential cannot be minted on a user's authority. This auth model requires a "
                + "session-authenticated host (CloudBeaver behind an OIDC proxy).");
        }
        return session;
    }

    private String resolvePrincipal(WebSession session) throws DBException {
        var user = session.getUser();
        String principal = user == null ? null : user.getUserId();
        if (principal == null || principal.isBlank()) {
            throw new DBException("The active session carries no user identity. Refusing to issue "
                + "an unattributable database credential.");
        }
        return principal;
    }

    private OpenBaoClient getClient() throws DBException {
        OpenBaoClient c = client;
        if (c == null) {
            synchronized (this) {
                c = client;
                if (c == null) {
                    c = new OpenBaoClient();
                    client = c;
                }
            }
        }
        return c;
    }
}
