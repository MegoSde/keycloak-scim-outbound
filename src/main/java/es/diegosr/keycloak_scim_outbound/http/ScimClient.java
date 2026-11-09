package es.diegosr.keycloak_scim_outbound.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import org.keycloak.component.ComponentModel;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;

/**
 * Minimal SCIM v2 client focused on Users resource.
 */
public class ScimClient {
    private final HttpClient http;
    private final String baseUrl;
    private final String bearer;
    private final Duration requestTimeout;
    private final int maxRetries;

    private static final ObjectMapper JSON = new ObjectMapper();

    public static ScimClient forTarget(ComponentModel target) {
        return new ScimClient(
                ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null),
                ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null),
                Duration.ofSeconds(8), 3,
                ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TRUSTED_CERTIFICATES, null));
    }

    public ScimClient(String baseUrl, String bearer) {
        this(baseUrl, bearer, Duration.ofSeconds(8), 3);
    }

    public ScimClient(String baseUrl, String bearer, Duration timeout, int maxRetries) {
        this(baseUrl, bearer, timeout, maxRetries, null);
    }

    public ScimClient(String baseUrl, String bearer, Duration timeout, int maxRetries, String trustedCertificatesPem) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.bearer = bearer;
        this.requestTimeout = timeout != null ? timeout : Duration.ofSeconds(8);
        this.maxRetries = Math.max(0, maxRetries);
        var builder = HttpClient.newBuilder()
                .connectTimeout(this.requestTimeout)
                .version(HttpClient.Version.HTTP_1_1);
        var sslContext = ScimTls.context(trustedCertificatesPem);
        if (sslContext != null) builder.sslContext(sslContext);
        this.http = builder.build();
    }

    public boolean smokeTest() {
        try {
            HttpRequest req = baseRequestBuilder("/ServiceProviderConfig").GET().build();
            HttpResponse<String> res = sendWithRetries(req);
            return is2xx(res.statusCode());
        } catch (Exception e) {
            httpErr("smokeTest failed: %s", e.getMessage());
            return false;
        }
    }

    public record ConnectionTestResult(boolean success, String code, String message, Integer status) { }

    /** A single read-only, authenticated request. No provisioning and no retries. */
    public ConnectionTestResult testConnection() {
        try {
            var response = http.send(baseRequestBuilder("/Users?count=0&attributes=id").GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status == 401) return testFailure("UNAUTHORIZED", "The SCIM server rejected the saved token (HTTP 401).", status);
            if (status == 403) return testFailure("FORBIDDEN", "The saved token does not have access to SCIM Users (HTTP 403).", status);
            if (status == 404) return testFailure("NOT_FOUND", "SCIM Users was not found. Check the saved SCIM Base URL (HTTP 404).", status);
            if (!is2xx(status)) return testFailure("HTTP_ERROR", "The SCIM server returned HTTP " + status + ".", status);
            JsonNode body;
            try { body = JSON.readTree(response.body()); }
            catch (Exception e) { return testFailure("INVALID_RESPONSE", "The server did not return a SCIM ListResponse. Check the SCIM Base URL.", status); }
            if (body == null || !body.isObject() || !body.path("totalResults").isIntegralNumber() || !body.path("totalResults").canConvertToInt()
                    || body.path("totalResults").asInt() < 0
                    || !body.path("schemas").isArray()
                    || !java.util.stream.StreamSupport.stream(body.path("schemas").spliterator(), false)
                            .anyMatch(schema -> schema.isTextual() && "urn:ietf:params:scim:api:messages:2.0:ListResponse".equals(schema.asText()))
                    || (body.has("Resources") && !body.path("Resources").isArray())) {
                return testFailure("INVALID_RESPONSE", "The server did not return a SCIM ListResponse. Check the SCIM Base URL.", status);
            }
            return new ConnectionTestResult(true, "OK",
                    "The SCIM Users endpoint accepted the saved configuration (HTTP " + status + "). No users or groups were changed.", status);
        } catch (javax.net.ssl.SSLException e) {
            String detail = String.valueOf(e.getMessage()).toLowerCase(java.util.Locale.ROOT);
            return detail.contains("subject alternative") || detail.contains("no name matching")
                    ? testFailure("TLS_HOSTNAME", "The server certificate does not match the hostname in the SCIM Base URL.", null)
                    : testFailure("TLS_ERROR", "TLS verification failed. Check the uploaded CA certificates, server certificate chain, and validity dates.", null);
        } catch (HttpTimeoutException e) {
            return testFailure("TIMEOUT", "The SCIM server did not respond before the timeout.", null);
        } catch (java.net.ConnectException e) {
            return testFailure("CONNECT_ERROR", "Could not connect to the SCIM server. Check the hostname, port, DNS and network access.", null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return testFailure("INTERRUPTED", "The connection test was interrupted. Try again.", null);
        } catch (Exception e) {
            return testFailure("CONNECTION_ERROR", "Could not complete the SCIM request. Check the saved URL and network access.", null);
        }
    }

    private static ConnectionTestResult testFailure(String code, String message, Integer status) {
        return new ConnectionTestResult(false, code, message, status);
    }

    /** Find user by userName and return SCIM id if present. */
    public Optional<String> findUserIdByUserName(String userName) {
        return findUserIdByFilter("userName", userName, "findUserIdByUserName");
    }

    /** Find user by externalId and return SCIM id if present. */
    public Optional<String> findUserIdByExternalId(String externalId) {
        return findUserIdByFilter("externalId", externalId, "findUserIdByExternalId");
    }

    private Optional<String> findUserIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();

        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query = lookupQuery(filter, attribute);
            HttpRequest req = baseRequestBuilder("/Users?" + query).GET().build();

            HttpResponse<String> res = sendWithRetries(req);
            if (is2xx(res.statusCode())) {
                String body = res.body();
                ScimListResponse users = parseListResponse(body, attribute, value);
                httpInfo("GET /Users?%s -> %d totalResults=%d", query, res.statusCode(), users.totalResults());
                if (users.matchingId().isPresent()) {
                    return users.matchingId();
                }
                if (!users.standardShape()) {
                    httpErr("Could not parse a standard SCIM ListResponse.");
                } else if (users.matchingResources() > 1) {
                    httpErr("Refusing ambiguous SCIM response: multiple Users match attribute %s.", attribute);
                } else if (users.totalResults() > 0 || users.resourcesPresent()) {
                    httpErr("Could not find a User whose %s matches the requested value and has an id.", attribute);
                }
            } else {
                httpErr("GET /Users?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            httpErr("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    static ScimListResponse parseListResponse(String body, String attribute, String expectedValue) throws Exception {
        if (body == null || body.isBlank()) {
            return new ScimListResponse(0, Optional.empty(), 0, 0, false);
        }

        JsonNode root = JSON.readTree(body);
        if (!root.isObject()) {
            return new ScimListResponse(0, Optional.empty(), 0, 0, false);
        }

        int totalResults = root.path("totalResults").asInt(0);
        JsonNode resources = root.path("Resources");
        boolean standardShape = root.path("totalResults").canConvertToInt()
                && (totalResults == 0 || resources.isArray());
        if (!resources.isArray() || resources.isEmpty()) {
            return new ScimListResponse(totalResults, Optional.empty(), 0, 0, standardShape);
        }

        String matchingId = null;
        int matchingResources = 0;
        for (JsonNode resource : resources) {
            JsonNode candidate = findAttribute(resource, attribute);
            if (candidate == null || !candidate.isTextual()
                    || !attributeValueMatches(attribute, candidate.asText(), expectedValue)) {
                continue;
            }

            matchingResources++;
            JsonNode id = findAttribute(resource, "id");
            if (matchingResources == 1 && id != null && id.isTextual() && !id.asText().isBlank()) {
                matchingId = id.asText();
            }
        }

        Optional<String> uniqueId = matchingResources == 1
                ? Optional.ofNullable(matchingId)
                : Optional.empty();
        return new ScimListResponse(
                totalResults, uniqueId, resources.size(), matchingResources, standardShape);
    }

    private static JsonNode findAttribute(JsonNode resource, String attribute) {
        JsonNode direct = resource.get(attribute);
        if (direct != null) return direct;

        var fields = resource.fields();
        while (fields.hasNext()) {
            var field = fields.next();
            if (field.getKey().equalsIgnoreCase(attribute)) return field.getValue();
        }
        return null;
    }

    private static boolean attributeValueMatches(String attribute, String actual, String expected) {
        if (actual == null || expected == null) return false;
        return "externalId".equals(attribute)
                ? actual.equals(expected)
                : actual.equalsIgnoreCase(expected);
    }

    /** Create SCIM user; returns true on 201/200. */
    public boolean createUser(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Users")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> res = sendWithRetries(req);
            if (res.statusCode() == 201 || res.statusCode() == 200) return true;

            if (res.statusCode() == 409) {
                httpInfo("POST /Users got 409 conflict: %s", safeBody(res));
            } else {
                httpErr("POST /Users -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            httpErr("POST /Users failed: %s", e.getMessage());
            return false;
        }
    }

    /** Patch SCIM user by id (RFC 7644 PatchOp). */
    public boolean patchUser(String id, String jsonPatch) {
        return sendJson("PATCH", userPath(id), jsonPatch, 200, 204);
    }

    public boolean deleteUser(String id) {
        String path = userPath(id);
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            HttpResponse<String> res = sendWithRetries(req);
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    /* ======================= Groups ======================= */

    /** Find group by displayName and return SCIM id if present. */
    public Optional<String> findGroupIdByDisplayName(String displayName) {
        return findGroupIdByFilter("displayName", displayName, "findGroupIdByDisplayName");
    }

    /** Find group by externalId and return SCIM id if present. */
    public Optional<String> findGroupIdByExternalId(String externalId) {
        return findGroupIdByFilter("externalId", externalId, "findGroupIdByExternalId");
    }

    private Optional<String> findGroupIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query = lookupQuery(filter, attribute);
            HttpRequest req = baseRequestBuilder("/Groups?" + query).GET().build();
            HttpResponse<String> res = sendWithRetries(req);
            if (is2xx(res.statusCode())) {
                ScimListResponse groups = parseListResponse(res.body(), attribute, value);
                httpInfo("GET /Groups?%s -> %d totalResults=%d", query, res.statusCode(), groups.totalResults());
                if (groups.matchingId().isPresent()) {
                    return groups.matchingId();
                }
                if (!groups.standardShape()) {
                    httpErr("Could not parse a standard SCIM ListResponse.");
                } else if (groups.matchingResources() > 1) {
                    httpErr("Refusing ambiguous SCIM response: multiple Groups match attribute %s.", attribute);
                } else if (groups.totalResults() > 0 || groups.resourcesPresent()) {
                    httpErr("Could not find a Group whose %s matches the requested value and has an id.", attribute);
                }
            } else {
                httpErr("GET /Groups?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            httpErr("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    /** Create SCIM group; returns true on 201/200. */
    public boolean createGroup(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Groups")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();
            HttpResponse<String> res = sendWithRetries(req);
            if (res.statusCode() == 201 || res.statusCode() == 200) return true;
            if (res.statusCode() == 409) {
                httpInfo("POST /Groups got 409 conflict: %s", safeBody(res));
            } else {
                httpErr("POST /Groups -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            httpErr("POST /Groups failed: %s", e.getMessage());
            return false;
        }
    }

    /** Patch SCIM group by id (RFC 7644 PatchOp). */
    public boolean patchGroup(String id, String jsonPatch) {
        return sendJson("PATCH", groupPath(id), jsonPatch, 200, 204);
    }

    /** Delete SCIM group by id. */
    public boolean deleteGroup(String id) {
        String path = groupPath(id);
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            HttpResponse<String> res = sendWithRetries(req);
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    /* ======================= internals ======================= */

    private boolean sendJson(String method, String path, String json, int... okCodes) {
        try {
            HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofString(json);
            HttpRequest.Builder b = baseRequestBuilder(path)
                    .header("Content-Type", "application/scim+json")
                    .method(method, body);

            HttpResponse<String> res = sendWithRetries(b.build());
            if (matches(res.statusCode(), okCodes)) return true;

            httpErr("%s %s -> %d %s", method, path, res.statusCode(), safeBody(res));
            return false;
        } catch (Exception e) {
            httpErr("%s %s failed: %s", method, path, e.getMessage());
            return false;
        }
    }

    private HttpRequest.Builder baseRequestBuilder(String pathOrQuery) {
        String url = this.baseUrl + (pathOrQuery.startsWith("/") ? pathOrQuery : "/" + pathOrQuery);
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(this.requestTimeout)
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/scim+json")
                .header("User-Agent", "keycloak-scim-outbound/1.0");
    }

    private HttpResponse<String> sendWithRetries(HttpRequest req) throws Exception {
        int attempt = 0;
        long backoff = 250L;
        while (true) {
            attempt++;
            HttpResponse<String> res;
            try {
                res = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                if (attempt > this.maxRetries) throw e;
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }

            int sc = res.statusCode();
            if (is2xx(sc)) return res;

            if ((sc == 429 || (sc >= 500 && sc <= 599)) && attempt <= this.maxRetries) {
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }
            return res;
        }
    }

    private static boolean is2xx(int code) { return code >= 200 && code < 300; }
    private static boolean matches(int code, int... okCodes) { for (int ok : okCodes) if (ok == code) return true; return false; }
    private static String trimTrailingSlash(String s) { if (s == null || s.isEmpty()) return s; return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }
    private static String userPath(String id)  { return "/Users/"  + urlEncode(id); }
    private static String groupPath(String id) { return "/Groups/" + urlEncode(id); }
    private static String lookupQuery(String filter, String attribute) {
        return "filter=" + urlEncode(filter) + "&attributes=" + urlEncode("id," + attribute);
    }
    private static String urlEncode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
    private static String safeBody(HttpResponse<String> res) { String b = res.body(); return b == null ? "" : (b.length() > 400 ? b.substring(0, 400) + " …" : b); }

    private static String scimFilterString(String value) { return "\"" + jsonEscape(value) + "\""; }
    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /* ===== timestamped logging (stdout/stderr) ===== */
    private static String now() { return java.time.OffsetDateTime.now().toString(); }
    private static void httpInfo(String fmt, Object... args) { System.out.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }
    private static void httpErr(String fmt, Object... args)  { System.err.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }

    record ScimListResponse(int totalResults, Optional<String> matchingId, int resourceCount,
                            int matchingResources, boolean standardShape) {
        boolean resourcesPresent() {
            return resourceCount > 0;
        }
    }
}
