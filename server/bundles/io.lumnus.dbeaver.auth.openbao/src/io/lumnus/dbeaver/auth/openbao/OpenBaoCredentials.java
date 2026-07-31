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
