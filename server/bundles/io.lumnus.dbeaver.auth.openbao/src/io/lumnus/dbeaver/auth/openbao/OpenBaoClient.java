/*
 * Lumnus substrate — OpenBao dynamic database credentials for DBeaver/CloudBeaver.
 * Licensed under the Apache License, Version 2.0 (same as the host project).
 */
package io.lumnus.dbeaver.auth.openbao;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jkiss.dbeaver.DBException;
import org.jkiss.dbeaver.Log;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * Minimal OpenBao client for the database secrets engine, operating <b>strictly on behalf of the
 * end user</b>.
 *
 * <h2>The one design rule</h2>
 * There is no service-identity path here, deliberately. The user's own OIDC access token is
 * exchanged at OpenBao's JWT auth method for a <em>user-scoped</em> OpenBao token, and the database
 * credential is requested with that. OpenBao therefore evaluates its own policies against the
 * authenticated user's identity and groups — it is structurally incapable of issuing a credential
 * to someone who is not entitled to it, rather than merely configured not to.
 *
 * <p>An earlier revision authenticated with the pod's ServiceAccount and passed the principal along
 * as a header. That made OpenBao issue on the <em>server's</em> authority, reducing the principal to
 * an audit annotation and leaving eligibility unenforced. A fallback to that mode is not provided,
 * because a fallback that silently downgrades the security model is worse than an outage.
 *
 * <p>Dependency-free beyond gson (reexported by {@code org.jkiss.dbeaver.model}) and the JDK HTTP
 * client — this sits on the connect path of every session.
 *
 * <p>Nothing secret is ever logged: only usernames, lease ids and principals appear, all of which
 * are needed for audit correlation and none of which are credentials.
 */
public class OpenBaoClient {

    private static final Log log = Log.getLog(OpenBaoClient.class);

    public static final String ENV_ADDR = "LUMNUS_OPENBAO_ADDR";
    public static final String ENV_CACERT = "LUMNUS_OPENBAO_CACERT";
    /** OpenBao JWT/OIDC auth mount path (the method configured against Keycloak). */
    public static final String ENV_JWT_AUTH_PATH = "LUMNUS_OPENBAO_JWT_AUTH_PATH";
    /** OpenBao JWT auth role that maps Keycloak claims/groups onto OpenBao policies. */
    public static final String ENV_JWT_ROLE = "LUMNUS_OPENBAO_JWT_ROLE";

    private static final String DEFAULT_ADDR = "https://vault.lab.lumnus.net:8200";
    private static final String DEFAULT_JWT_AUTH_PATH = "jwt";
    private static final String DEFAULT_JWT_ROLE = "cloudbeaver";

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String address;
    private final String jwtAuthPath;
    private final String jwtRole;
    private final HttpClient http;

    public OpenBaoClient() throws DBException {
        this.address = trimTrailingSlash(envOr(ENV_ADDR, DEFAULT_ADDR));
        this.jwtAuthPath = envOr(ENV_JWT_AUTH_PATH, DEFAULT_JWT_AUTH_PATH);
        this.jwtRole = envOr(ENV_JWT_ROLE, DEFAULT_JWT_ROLE);
        this.http = buildHttpClient();
    }

    /**
     * Issue a short-lived database credential <em>as the user</em>.
     *
     * @param userAccessToken the authenticated user's OIDC access token (forwarded by the proxy)
     * @param dbRole          the OpenBao database role, e.g. {@code substrate-ro}
     * @param principal       the user, for log correlation only — authority comes from the token
     */
    public DynamicCredential issueForUser(String userAccessToken, String dbRole, String principal)
        throws DBException {
        // 1. Exchange the user's OIDC token for a user-scoped OpenBao token. Deliberately NOT
        //    cached across users or sessions — the token IS the identity.
        String userToken = exchangeUserToken(userAccessToken, principal);

        // 2. Request the credential on that token. If the user's policies do not permit this role,
        //    OpenBao refuses here — which is the entire point.
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(address + "/v1/database/creds/" + dbRole))
            .timeout(TIMEOUT)
            .header("X-Vault-Token", userToken)
            .GET()
            .build();

        JsonObject body = send(req, "issue credentials for role '" + dbRole + "' as " + principal);
        JsonObject data = body.getAsJsonObject("data");
        if (data == null || !data.has("username") || !data.has("password")) {
            throw new DBException("OpenBao returned no credential for role '" + dbRole + "'.");
        }
        String leaseId = body.has("lease_id") ? body.get("lease_id").getAsString() : null;
        log.debug("OpenBao issued db credential user=" + data.get("username").getAsString()
            + " role=" + dbRole + " principal=" + principal + " lease=" + leaseId);

        return new DynamicCredential(
            data.get("username").getAsString(),
            data.get("password").getAsString(),
            leaseId);
    }

    /** Exchange the user's OIDC access token for a user-scoped OpenBao token. */
    private String exchangeUserToken(String userAccessToken, String principal) throws DBException {
        JsonObject payload = new JsonObject();
        payload.addProperty("role", jwtRole);
        payload.addProperty("jwt", userAccessToken);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(address + "/v1/auth/" + jwtAuthPath + "/login"))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload.toString(), StandardCharsets.UTF_8))
            .build();

        JsonObject body = send(req, "exchange the access token of '" + principal + "' at OpenBao");
        JsonObject auth = body.getAsJsonObject("auth");
        if (auth == null || !auth.has("client_token")) {
            throw new DBException("OpenBao JWT login returned no client_token for " + principal);
        }
        // NB: login returns lease_duration and policies under `auth`, NOT `data` — reading them
        // from `data` yields a silent false negative. This substrate has paid for that once.
        if (log.isDebugEnabled()) {
            log.debug("OpenBao JWT login OK principal=" + principal
                + " policies=" + auth.get("policies")
                + " ttl=" + (auth.has("lease_duration") ? auth.get("lease_duration") : "?") + "s");
        }
        return auth.get("client_token").getAsString();
    }

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────

    private JsonObject send(HttpRequest req, String what) throws DBException {
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new DBException("Could not reach OpenBao at " + address + " to " + what + ".", e);
        }
        if (resp.statusCode() / 100 != 2) {
            // Surfaces OpenBao's own error text: it distinguishes "role missing" from "permission
            // denied" from "token expired", which a generic message would flatten into a guess.
            throw new DBException("OpenBao refused to " + what + " (HTTP " + resp.statusCode()
                + "): " + resp.body());
        }
        return JsonParser.parseString(resp.body()).getAsJsonObject();
    }

    private HttpClient buildHttpClient() throws DBException {
        HttpClient.Builder b = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER);
        String caPath = System.getenv(ENV_CACERT);
        if (caPath != null && !caPath.isBlank()) {
            b.sslContext(trustOnly(caPath));
        }
        return b.build();
    }

    /** Trust only the given CA PEM — the substrate's OpenBao uses a private CA. */
    private SSLContext trustOnly(String caPath) throws DBException {
        try (InputStream in = Files.newInputStream(Path.of(caPath))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (var cert : cf.generateCertificates(in)) {
                ks.setCertificateEntry("openbao-ca-" + (i++), (X509Certificate) cert);
            }
            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (Exception e) {
            throw new DBException("Could not build a trust store from " + ENV_CACERT + "=" + caPath, e);
        }
    }

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private static String trimTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    /** An issued short-lived credential. Never persisted, never logged. */
    public record DynamicCredential(String username, String password, String leaseId) {
    }
}
