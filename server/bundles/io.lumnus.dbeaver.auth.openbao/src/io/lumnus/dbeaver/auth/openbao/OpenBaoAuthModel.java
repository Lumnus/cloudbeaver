/*
 * Lumnus substrate — OpenBao dynamic database credentials for DBeaver/CloudBeaver.
 * Licensed under the Apache License, Version 2.0 (same as the host project).
 */
package io.lumnus.dbeaver.auth.openbao;

import org.jkiss.code.NotNull;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;
import org.jkiss.dbeaver.model.DBPDataSource;
import org.jkiss.dbeaver.model.DBPDataSourceContainer;
import org.jkiss.dbeaver.model.access.DBACredentialsProvider;
import org.jkiss.dbeaver.model.app.DBPDataSourceRegistry;
import org.jkiss.dbeaver.model.auth.SMCredentials;
import org.jkiss.dbeaver.model.auth.SMCredentialsProvider;
import org.jkiss.dbeaver.model.connection.DBPConnectionConfiguration;
import org.jkiss.dbeaver.model.exec.DBCException;
import org.jkiss.dbeaver.model.impl.auth.AuthModelDatabaseNative;
import org.jkiss.dbeaver.model.runtime.DBRProgressMonitor;

import java.util.Properties;

/**
 * Auth model that issues a <em>fresh, short-lived</em> database credential from OpenBao on every
 * connect, scoped to the authenticated principal.
 *
 * <h2>Why this shape</h2>
 * dbeaver-core's auth models are a public extension point
 * ({@code org.jkiss.dbeaver.dataSourceAuth}) and CloudBeaver enumerates them from the core registry
 * at runtime. So this is an <em>additive bundle</em>, not a patch of either project: it survives
 * host version bumps, and it is structurally the same move dbeaver's own {@code AuthModelPgPass}
 * makes — resolve the password from an external source at connect time, rather than from anything
 * stored on the connection.
 *
 * <h2>Identity</h2>
 * CloudBeaver binds the authenticated web session into the datasource registry as its credentials
 * provider ({@code dataSourceRegistry.setAuthCredentialsProvider(webSession)}), and
 * {@code WebSession} implements both {@code DBACredentialsProvider} and
 * {@code SMCredentialsProvider}. So the connect path can see <em>who</em> is asking, and this model
 * <b>refuses to mint anything when it cannot</b> — an unattributable credential is worse than a
 * failed connection.
 *
 * <h2>What it deliberately does not do</h2>
 * {@link #saveCredentials} is a no-op. The base class writes the resolved username and password back
 * into the connection configuration, which for an ephemeral credential would persist a secret that
 * is dead within the hour and defeat the entire point. Credentials are supplied for the connect and
 * then forgotten.
 */
public class OpenBaoAuthModel extends AuthModelDatabaseNative<OpenBaoCredentials> {

    private static final Log log = Log.getLog(OpenBaoAuthModel.class);

    /** OpenBao database role to request, e.g. {@code substrate-ro}. Required. */
    public static final String PROP_ROLE = "openbao.role";
    /**
     * Optional coarse eligibility gate evaluated inside the server's trust boundary. Real
     * per-principal eligibility belongs broker-side — see the README.
     */
    public static final String PROP_REQUIRED_PERMISSION = "openbao.requiredPermission";

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
        // Deliberately NOT calling super: the whole point is that nothing stored on the connection
        // is used as a credential. The username and password come from OpenBao or not at all.
        try {
            String role = configuration.getAuthProperty(PROP_ROLE);
            if (role == null || role.isBlank()) {
                throw new DBException("Connection does not declare an OpenBao role. "
                    + "Set the '" + PROP_ROLE + "' authentication property (e.g. 'substrate-ro').");
            }

            String principal = resolvePrincipal(dataSource, configuration);
            credentials.setPrincipal(principal);

            OpenBaoClient.DynamicCredential issued = getClient().issue(role, principal);
            credentials.setUserName(issued.username());
            credentials.setUserPassword(issued.password());
            credentials.setLeaseId(issued.leaseId());
            credentials.setResolutionError(null);
        } catch (Throwable e) {
            // Deferred to initAuthentication — loadCredentials is also invoked outside connect.
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

    /**
     * No-op by design — an ephemeral credential must never be written back into the stored
     * connection configuration. See the class comment.
     */
    @Override
    public void saveCredentials(
        @NotNull DBPDataSourceContainer dataSource,
        @NotNull DBPConnectionConfiguration configuration,
        @NotNull OpenBaoCredentials credentials
    ) {
        // intentionally empty
    }

    /**
     * Supplies the credential for <em>this</em> connect only. Distinct from
     * {@link #saveCredentials}, whose contract is persistence.
     */
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

    /**
     * Resolve the authenticated principal, or refuse.
     *
     * <p>The cast to {@code SMCredentialsProvider} is what makes this identity-aware, and it holds
     * because CloudBeaver's {@code WebSession} implements both interfaces. In a plain DBeaver
     * desktop runtime the provider is something else — in which case there is no authenticated
     * principal to scope a credential to, and refusing is the correct outcome rather than silently
     * minting an unattributable one.
     */
    private String resolvePrincipal(
        DBPDataSourceContainer dataSource,
        DBPConnectionConfiguration configuration
    ) throws DBException {
        DBPDataSourceRegistry registry = dataSource.getRegistry();
        DBACredentialsProvider provider = registry == null ? null : registry.getAuthCredentialsProvider();

        if (!(provider instanceof SMCredentialsProvider smProvider)) {
            throw new DBException("No authenticated session is bound to this connection, so a "
                + "credential cannot be scoped to a principal. This auth model requires a "
                + "session-authenticated host (CloudBeaver).");
        }
        SMCredentials smCredentials = smProvider.getActiveUserCredentials();
        if (smCredentials == null || smCredentials.getUserId() == null
            || smCredentials.getUserId().isBlank()) {
            throw new DBException("The active session carries no user identity. Refusing to issue "
                + "an unattributable database credential.");
        }
        String principal = smCredentials.getUserId();

        String required = configuration.getAuthProperty(PROP_REQUIRED_PERMISSION);
        if (required != null && !required.isBlank()
            && !smCredentials.getPermissions().contains(required)) {
            throw new DBException("Principal '" + principal + "' does not hold the permission '"
                + required + "' required by this connection.");
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
