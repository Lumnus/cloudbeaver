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
import java.time.Instant;

/**
 * Minimal OpenBao client for the database secrets engine.
 *
 * <p>Deliberately dependency-free beyond gson (reexported by {@code org.jkiss.dbeaver.model}) and
 * the JDK's own HTTP client — an auth model sits on the connect path of every session, so its
 * dependency surface is kept as small as the job allows.
 *
 * <p><b>How it authenticates to OpenBao.</b> Kubernetes auth by default: the pod's ServiceAccount
 * JWT is exchanged for a short-lived OpenBao token. That is the correct shape for an in-cluster
 * workload — no static token is stored anywhere. A token file is supported as a fallback for
 * out-of-cluster development only.
 *
 * <p><b>What it never does.</b> It never logs, echoes, or persists a credential value. Only the
 * username, the lease id and the principal appear in logs — all non-secret and all needed for
 * audit correlation.
 */
public class OpenBaoClient {

    private static final Log log = Log.getLog(OpenBaoClient.class);

    // Deployment-level configuration. Environment rather than connection config: the endpoint and
    // the pod's own identity are properties of the deployment, not of any single connection.
    public static final String ENV_ADDR = "LUMNUS_OPENBAO_ADDR";
    public static final String ENV_CACERT = "LUMNUS_OPENBAO_CACERT";
    public static final String ENV_K8S_ROLE = "LUMNUS_OPENBAO_K8S_ROLE";
    public static final String ENV_K8S_AUTH_PATH = "LUMNUS_OPENBAO_K8S_AUTH_PATH";
    public static final String ENV_TOKEN_FILE = "LUMNUS_OPENBAO_TOKEN_FILE";

    private static final String DEFAULT_ADDR = "https://vault.lab.lumnus.net:8200";
    private static final String DEFAULT_K8S_AUTH_PATH = "kubernetes";
    private static final String SA_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    /** Renew a little before actual expiry so a connect never races the token's death. */
    private static final Duration TOKEN_SKEW = Duration.ofSeconds(30);

    private final String address;
    private final HttpClient http;

    private String cachedToken;
    private Instant cachedTokenExpiry = Instant.EPOCH;

    public OpenBaoClient() throws DBException {
        this.address = trimTrailingSlash(envOr(ENV_ADDR, DEFAULT_ADDR));
        this.http = buildHttpClient();
    }

    /**
     * Issue a short-lived database credential.
     *
     * @param role      the database role configured on the OpenBao side (e.g. {@code substrate-ro})
     * @param principal the authenticated principal — sent as a header purely so the OpenBao audit
     *                  log records <em>who</em> the credential was minted for. It is not a
     *                  substitute for authorization: see the eligibility note in the README.
     */
    public DynamicCredential issue(String role, String principal) throws DBException {
        String token = clientToken();
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(address + "/v1/database/creds/" + role))
            .timeout(TIMEOUT)
            .header("X-Vault-Token", token)
            .header("X-Lumnus-Principal", principal)
            .GET()
            .build();

        JsonObject body = send(req, "issue credentials for role '" + role + "'");
        JsonObject data = body.getAsJsonObject("data");
        if (data == null || !data.has("username") || !data.has("password")) {
            throw new DBException("OpenBao returned no credential for role '" + role
                + "'. Check that the role exists and the database connection is configured.");
        }
        String leaseId = body.has("lease_id") ? body.get("lease_id").getAsString() : null;
        log.debug("OpenBao issued credential user=" + data.get("username").getAsString()
            + " role=" + role + " principal=" + principal + " lease=" + leaseId);

        return new DynamicCredential(
            data.get("username").getAsString(),
            data.get("password").getAsString(),
            leaseId);
    }

    // ── auth ──────────────────────────────────────────────────────────────────────────────────

    private synchronized String clientToken() throws DBException {
        if (cachedToken != null && Instant.now().isBefore(cachedTokenExpiry)) {
            return cachedToken;
        }
        String tokenFile = System.getenv(ENV_TOKEN_FILE);
        if (tokenFile != null && !tokenFile.isBlank()) {
            // Out-of-cluster development fallback. Not the production path.
            cachedToken = readFile(tokenFile, "OpenBao token file");
            cachedTokenExpiry = Instant.now().plus(Duration.ofMinutes(5));
            return cachedToken;
        }
        return loginWithKubernetes();
    }

    private String loginWithKubernetes() throws DBException {
        String role = System.getenv(ENV_K8S_ROLE);
        if (role == null || role.isBlank()) {
            throw new DBException("OpenBao Kubernetes auth is not configured: set " + ENV_K8S_ROLE
                + " (or " + ENV_TOKEN_FILE + " for out-of-cluster development).");
        }
        String jwt = readFile(SA_JWT_PATH, "Kubernetes ServiceAccount token");
        String authPath = envOr(ENV_K8S_AUTH_PATH, DEFAULT_K8S_AUTH_PATH);

        JsonObject payload = new JsonObject();
        payload.addProperty("role", role);
        payload.addProperty("jwt", jwt);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(address + "/v1/auth/" + authPath + "/login"))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload.toString(), StandardCharsets.UTF_8))
            .build();

        JsonObject body = send(req, "authenticate to OpenBao via Kubernetes auth");
        JsonObject auth = body.getAsJsonObject("auth");
        if (auth == null || !auth.has("client_token")) {
            throw new DBException("OpenBao Kubernetes login returned no client_token.");
        }
        // NB: token-create/login returns lease_duration under `auth`, NOT `data`. Reading it from
        // `data` yields a silent false negative — a defect this substrate has already paid for once.
        long ttl = auth.has("lease_duration") ? auth.get("lease_duration").getAsLong() : 300L;

        cachedToken = auth.get("client_token").getAsString();
        cachedTokenExpiry = Instant.now().plusSeconds(Math.max(ttl, 1)).minus(TOKEN_SKEW);
        log.debug("OpenBao Kubernetes login OK, role=" + role + " ttl=" + ttl + "s");
        return cachedToken;
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
            // Deliberately surfaces OpenBao's own error text — it distinguishes "role missing" from
            // "permission denied" from "engine not mounted", which a generic message would flatten.
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

    /**
     * Build an SSL context trusting only the given CA PEM. The substrate's OpenBao is issued by a
     * private CA; this avoids requiring a rebuilt JVM truststore in the container image.
     */
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

    private static String readFile(String path, String what) throws DBException {
        try {
            return Files.readString(Path.of(path)).trim();
        } catch (Exception e) {
            throw new DBException("Could not read " + what + " at " + path, e);
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
