package es.diegosr.keycloak_scim_outbound.http;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import es.diegosr.keycloak_scim_outbound.sync.ScimUserSync;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.*;

class ScimTlsTest {
    @TempDir Path directory;

    private KeyStore store(String name) throws Exception {
        Path file = directory.resolve(name + ".p12");
        Process process = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-validity", "30",
                "-storetype", "PKCS12", "-keystore", file.toString(), "-storepass", "test-password",
                "-keypass", "test-password", "-noprompt").redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        assertEquals(0, process.waitFor(), output);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(file)) { store.load(input, "test-password".toCharArray()); }
        return store;
    }

    private String pem(KeyStore store) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(store.getCertificate("server").getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    @Test void validatesAndNormalizesBundles() throws Exception {
        String certificate = pem(store("valid"));
        assertEquals(certificate + certificate, ScimTls.normalize(" \n" + certificate + "\n" + certificate));
        assertEquals("", ScimTls.normalize(null));
        assertNull(ScimTls.context(""));
        assertThrows(IllegalArgumentException.class, () -> ScimTls.normalize("not a certificate"));
        assertThrows(IllegalArgumentException.class, () -> ScimTls.normalize(certificate + "-----BEGIN PRIVATE KEY-----"));
        assertThrows(IllegalArgumentException.class, () -> ScimTls.normalize(certificate.repeat(17)));
        assertThrows(IllegalArgumentException.class, () -> ScimTls.normalize("x".repeat(ScimTls.MAX_PEM_LENGTH + 1)));
        assertThrows(IllegalArgumentException.class, () -> ScimTls.normalize("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
    }

    @Test void validationRejectsBadUploadAndSupportsRemoval() throws Exception {
        var factory = new ScimTargetProviderFactory();
        var target = new ComponentModel();
        target.getConfig().putSingle("baseUrl", "https://localhost/scim/v2");
        target.getConfig().putSingle("token", "test");
        target.getConfig().putSingle("trustedCertificatesPem", "invalid");
        assertThrows(ComponentValidationException.class, () -> factory.validateConfiguration(null, null, target));
        assertEquals("invalid", target.getConfig().getFirst("trustedCertificatesPem"));
        String certificate = pem(store("validation"));
        target.getConfig().putSingle("trustedCertificatesPem", "\n" + certificate);
        factory.validateConfiguration(null, null, target);
        assertEquals(certificate, target.getConfig().getFirst("trustedCertificatesPem"));
        target.getConfig().putSingle("trustedCertificatesPem", "");
        factory.validateConfiguration(null, null, target);
        assertFalse(target.getConfig().containsKey("trustedCertificatesPem"));
    }

    @Test void targetTrustIsIsolatedAndHostnameVerificationRemainsEnabled() throws Exception {
        KeyStore serverStore = store("server");
        String certificate = pem(serverStore);
        String otherCertificate = pem(store("other"));
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(serverStore, "test-password".toCharArray());
        var serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
        var defaultContext = SSLContext.getDefault();
        var server = HttpsServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        com.sun.net.httpserver.HttpHandler handler = exchange -> {
            byte[] body = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],\"totalResults\":0}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        };
        server.createContext("/ServiceProviderConfig", handler);
        server.createContext("/Users", handler);
        server.start();
        try {
            String url = "https://localhost:" + server.getAddress().getPort();
            var target = new ComponentModel();
            target.getConfig().putSingle("baseUrl", url);
            target.getConfig().putSingle("token", "test");
            target.getConfig().putSingle("trustedCertificatesPem", certificate);
            assertTrue(ScimClient.forTarget(target).smokeTest());
            assertTrue(ScimClient.forTarget(target).testConnection().success());
            assertFalse(new ScimClient(url, "test", Duration.ofSeconds(2), 0, otherCertificate).smokeTest());
            assertFalse(new ScimClient(url, "test", Duration.ofSeconds(2), 0).smokeTest());
            assertFalse(new ScimClient(url.replace("localhost", "127.0.0.1"), "test", Duration.ofSeconds(2), 0, certificate).smokeTest());
            target.getConfig().putSingle("trustedCertificatesPem", otherCertificate);
            assertFalse(ScimClient.forTarget(target).smokeTest());
            target.getConfig().putSingle("trustedCertificatesPem", certificate);
            assertTrue(ScimClient.forTarget(target).smokeTest());
            assertEquals("TLS_HOSTNAME", new ScimClient(url.replace("localhost", "127.0.0.1"), "test", Duration.ofSeconds(2), 0, certificate).testConnection().code());
            assertEquals("TLS_ERROR", new ScimClient(url, "test", Duration.ofSeconds(2), 0, otherCertificate).testConnection().code());
            assertSame(defaultContext, SSLContext.getDefault());
        } finally { server.stop(0); }
    }

    @Test void fullSyncUsesTheTargetsUploadedCertificate() throws Exception {
        KeyStore serverStore = store("full-sync");
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(serverStore, "test-password".toCharArray());
        var serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
        var defaultContext = SSLContext.getDefault();
        var server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        var creates = new AtomicInteger();
        server.createContext("/Users", exchange -> {
            boolean create = "POST".equals(exchange.getRequestMethod());
            if (create) creates.incrementAndGet();
            byte[] body = (create ? "{}" : "{\"totalResults\":0,\"Resources\":[]}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(create ? 201 : 200, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        server.start();
        try {
            var target = new ComponentModel();
            target.getConfig().putSingle("baseUrl", "https://localhost:" + server.getAddress().getPort());
            target.getConfig().putSingle("token", "test");
            target.getConfig().putSingle("trustedCertificatesPem", pem(serverStore));
            var session = mock(KeycloakSession.class);
            var realm = mock(RealmModel.class);
            var users = mock(UserProvider.class);
            var user = mock(UserModel.class);
            when(session.users()).thenReturn(users);
            when(user.getId()).thenReturn("never-synced");
            when(user.getUsername()).thenReturn("alice");
            when(users.searchForUserStream(realm, Map.of(), 0,
                    ScimUserSync.PAGE_SIZE))
                    .thenReturn(Stream.of(user));
            var result = new ScimUserSync()
                    .syncPage(session, realm, target, 0).result();
            assertEquals(1, result.getAdded());
            assertEquals(0, result.getFailed());
            assertEquals(1, creates.get());
            assertSame(defaultContext, SSLContext.getDefault());
        } finally { server.stop(0); }
    }

}
