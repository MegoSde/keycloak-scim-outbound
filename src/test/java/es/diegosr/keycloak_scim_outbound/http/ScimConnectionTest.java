package es.diegosr.keycloak_scim_outbound.http;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class ScimConnectionTest {
    private static final String LIST = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],\"totalResults\":0,\"Resources\":[]}";

    @Test void usesOnlyAuthenticatedGetAndReportsHttpAndProtocolFailuresWithoutRetrying() throws Exception {
        var status = new AtomicInteger(200);
        var requests = new AtomicInteger();
        var body = new java.util.concurrent.atomic.AtomicReference<>(LIST);
        var problem = new java.util.concurrent.atomic.AtomicReference<String>();
        var server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/scim/v2/Users", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())
                    || !"count=0&attributes=id".equals(exchange.getRequestURI().getRawQuery())
                    || !"Bearer saved-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                problem.set("Unexpected request method, URL or credentials");
            }
            requests.incrementAndGet();
            byte[] content = body.get().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status.get(), content.length);
            try (var output = exchange.getResponseBody()) { output.write(content); }
        });
        server.start();
        try {
            var client = new ScimClient("http://localhost:" + server.getAddress().getPort() + "/scim/v2", "saved-token");
            assertTrue(client.testConnection().success());
            for (int code : new int[] {302, 401, 403, 404, 429, 500}) {
                status.set(code); int before = requests.get();
                var result = client.testConnection();
                assertFalse(result.success()); assertEquals(code, result.status());
                assertEquals(before + 1, requests.get(), "Connection tests must not retry");
                assertFalse(result.message().contains("saved-token"));
            }
            status.set(200); body.set("<html>login page</html>");
            assertEquals("INVALID_RESPONSE", client.testConnection().code());
            body.set("{}"); assertEquals("INVALID_RESPONSE", client.testConnection().code());
            body.set(LIST.replace("ListResponse", "ListResponse-invalid"));
            assertEquals("INVALID_RESPONSE", client.testConnection().code());
            body.set(LIST.replace("\"totalResults\":0", "\"totalResults\":0.5"));
            assertEquals("INVALID_RESPONSE", client.testConnection().code());
            assertNull(problem.get());
        } finally { server.stop(0); }
    }
}
