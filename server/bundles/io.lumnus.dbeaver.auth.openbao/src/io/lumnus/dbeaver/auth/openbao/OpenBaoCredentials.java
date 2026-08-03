/*
 * Lumnus substrate — OpenBao dynamic database credentials for DBeaver/CloudBeaver.
 * Licensed under the Apache License, Version 2.0 (same as the host project).
 */
package io.lumnus.dbeaver.auth.openbao;

import org.jkiss.dbeaver.model.impl.auth.AuthModelDatabaseNativeCredentials;

/**
 * Credentials resolved from OpenBao at connect time.
 *
 * <p>Carries the resolution error rather than throwing during {@code loadCredentials}, mirroring
 * how dbeaver-core's own {@code AuthModelPgPass} defers its failure — {@code loadCredentials} is
 * also called on non-connect paths (config UI, validation), so throwing there produces confusing
 * failures far from the actual connect attempt. The error is raised in
 * {@link OpenBaoAuthModel#initAuthentication} instead, where a user is genuinely trying to connect.
 */
public class OpenBaoCredentials extends AuthModelDatabaseNativeCredentials {

    private String leaseId;
    private String principal;
    private Throwable resolutionError;

    // ── Suppress the inherited username/password FORM FIELDS ──────────────────────────────────
    // AuthModelDatabaseNativeCredentials annotates getUserName()/getUserPassword() with @Property,
    // so any subclass inherits them as editable connection properties — and CloudBeaver duly puts
    // up a credentials dialog before connecting. For this model that dialog is not just noise, it
    // is a contradiction: the whole point is that the credential is minted from OpenBao against the
    // authenticated principal at connect time, and nothing is stored on the connection. Asking the
    // user to type a username and password invites them to supply the very static credential this
    // replaces.
    //
    // Overriding the getters WITHOUT re-declaring @Property removes them from the property set —
    // the property scanner reads annotations from the most-derived declaration. This is exactly how
    // CE's own zero-input model does it (OracleAuthOSCredentials, the `oracle_os` "OS
    // Authentication" model, which reports no properties for the same reason).
    //
    // The FIELDS still exist and are still used: initAuthentication() writes the minted username
    // and password into them via the inherited setters, and the JDBC layer reads them back. Only
    // their exposure as user-editable properties is withdrawn.

    @Override
    public String getUserName() {
        return super.getUserName();
    }

    @Override
    public String getUserPassword() {
        return super.getUserPassword();
    }

    /** OpenBao lease id for the issued credential — carried for audit correlation only. */
    public String getLeaseId() {
        return leaseId;
    }

    public void setLeaseId(String leaseId) {
        this.leaseId = leaseId;
    }

    /** The authenticated principal the credential was issued for. */
    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public Throwable getResolutionError() {
        return resolutionError;
    }

    public void setResolutionError(Throwable resolutionError) {
        this.resolutionError = resolutionError;
    }
}
