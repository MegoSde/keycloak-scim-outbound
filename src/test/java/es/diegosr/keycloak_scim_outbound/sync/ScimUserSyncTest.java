package es.diegosr.keycloak_scim_outbound.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ScimUserSyncTest {
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserProvider users = mock(UserProvider.class);
    private final ScimClient client = mock(ScimClient.class);
    private final ComponentModel target = new ComponentModel();
    private final ScimUserSync sync = new ScimUserSync((base, token) -> client);

    ScimUserSyncTest() {
        target.setId("selected-target");
        target.getConfig().putSingle("baseUrl", "https://scim.example/scim/v2");
        target.getConfig().putSingle("token", "test-token");
        when(session.users()).thenReturn(users);
        when(client.findUserIdByExternalId(anyString())).thenReturn(Optional.empty());
        when(client.findUserIdByUserName(anyString())).thenReturn(Optional.empty());
        when(client.createUser(anyString())).thenReturn(true);
        when(client.patchUser(anyString(), anyString())).thenReturn(true);
    }

    @Test
    void createsUsersWithNoEventsOrMembershipMarkersAndUpdatesExistingUsers() {
        UserModel fresh = user("fresh"), existing = user("existing");
        page(0, fresh, existing);
        when(client.findUserIdByExternalId("existing")).thenReturn(Optional.of("remote-id"));
        var result = sync.syncPage(session, realm, target, 0).result();
        assertEquals(1, result.getAdded());
        assertEquals(1, result.getUpdated());
        assertEquals(0, result.getFailed());
        verify(client).createUser(contains("\"externalId\": \"fresh\""));
        verify(client).patchUser(eq("remote-id"), contains("existing"));
        verify(fresh, never()).getAttributeStream(anyString());
        verifyNoInteractions(realm);
    }

    @Test
    void honoursGroupFilterAndSkipsServiceAccounts() {
        target.getConfig().putSingle("filterGroup", "employees");
        UserModel member = user("member"), outsider = user("outsider"), service = user("service");
        GroupModel group = mock(GroupModel.class);
        when(group.getName()).thenReturn("employees");
        when(member.getGroupsStream()).thenReturn(Stream.of(group));
        when(outsider.getGroupsStream()).thenReturn(Stream.empty());
        when(service.getServiceAccountClientLink()).thenReturn("client");
        page(0, member, outsider, service);
        var result = sync.syncPage(session, realm, target, 0).result();
        assertEquals(1, result.getAdded());
        verify(client, times(1)).createUser(anyString());
        verify(client, never()).findUserIdByExternalId("outsider");
        verify(client, never()).findUserIdByExternalId("service");
    }

    @Test
    void usesEmailStrategyAndPreservesDisabledStatus() {
        target.getConfig().putSingle("userNameStrategy", "email");
        UserModel user = user("disabled");
        when(user.getEmail()).thenReturn("person@example.org");
        when(user.isEnabled()).thenReturn(false);
        page(0, user);
        assertEquals(1, sync.syncPage(session, realm, target, 0).result().getAdded());
        verify(client).createUser(argThat(payload -> payload.contains("\"userName\": \"person@example.org\"")
                && payload.contains("\"active\": false")));
    }

    @Test
    void honoursCustomUsernameAttributeAndFailsMissingValues() {
        target.getConfig().putSingle("userNameStrategy", "attribute");
        target.getConfig().putSingle("userNameAttribute", "mailId");
        UserModel good = user("good"), missing = user("missing");
        when(good.getFirstAttribute("mailId")).thenReturn("custom-name");
        page(0, good, missing);
        var result = sync.syncPage(session, realm, target, 0).result();
        assertEquals(1, result.getAdded());
        assertEquals(1, result.getFailed());
        verify(client).findUserIdByUserName("custom-name");
        verify(client, never()).findUserIdByExternalId("missing");
    }

    @Test
    void continuesAfterIndividualFailuresAndCountsThem() {
        page(0, user("broken"), user("rejected"), user("good"));
        when(client.findUserIdByExternalId("broken")).thenThrow(new IllegalStateException("private details"));
        when(client.findUserIdByExternalId("rejected")).thenReturn(Optional.of("rejected-id"));
        when(client.patchUser(eq("rejected-id"), anyString())).thenReturn(false);
        var result = sync.syncPage(session, realm, target, 0).result();
        assertEquals(2, result.getFailed());
        assertEquals(1, result.getAdded());
    }

    @Test
    void recoversFromConcurrentCreationUsingUsernameFallback() {
        page(0, user("racing"));
        when(client.createUser(anyString())).thenReturn(false);
        when(client.findUserIdByUserName("racing")).thenReturn(Optional.empty(), Optional.of("race-id"));
        var result = sync.syncPage(session, realm, target, 0).result();
        assertEquals(1, result.getUpdated());
        assertEquals(0, result.getFailed());
        verify(client).patchUser(eq("race-id"), anyString());
    }

    @Test
    void passesPaginationToAggregatedUserProviderAndClosesStream() {
        AtomicInteger closed = new AtomicInteger();
        UserModel later = user("later-page");
        when(users.searchForUserStream(realm, Map.of(), 100, ScimUserSync.PAGE_SIZE))
                .thenReturn(Stream.of(later).onClose(closed::incrementAndGet));
        var page = sync.syncPage(session, realm, target, 100);
        assertEquals(1, page.scanned());
        assertEquals(1, closed.get());
        assertEquals(1, page.result().getAdded());
    }

    @Test
    void repeatedSyncAgainstHttpEndpointCreatesOnceThenUpdates() throws Exception {
        AtomicInteger creates = new AtomicInteger(), patches = new AtomicInteger();
        ObjectMapper json = new ObjectMapper();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/scim/v2/Users", exchange -> {
            assertEquals("Bearer test-token", exchange.getRequestHeaders().getFirst("Authorization"));
            String body = "{}";
            int status = 200;
            switch (exchange.getRequestMethod()) {
                case "GET" -> body = creates.get() == 0
                        ? "{\"totalResults\":0,\"Resources\":[]}"
                        : "{\"totalResults\":1,\"Resources\":[{\"id\":\"remote\",\"externalId\":\"fresh\",\"userName\":\"fresh\"}]}";
                case "POST" -> {
                    assertEquals("fresh", json.readTree(exchange.getRequestBody()).path("externalId").asText());
                    creates.incrementAndGet();
                    status = 201;
                }
                case "PATCH" -> {
                    assertEquals("/scim/v2/Users/remote", exchange.getRequestURI().getPath());
                    patches.incrementAndGet();
                }
                default -> throw new AssertionError("Unexpected destructive request");
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            target.getConfig().putSingle("baseUrl", "http://127.0.0.1:" + server.getAddress().getPort() + "/scim/v2");
            UserModel user = user("fresh");
            when(users.searchForUserStream(realm, Map.of(), 0, ScimUserSync.PAGE_SIZE))
                    .thenAnswer(invocation -> Stream.of(user));
            ScimUserSync real = new ScimUserSync();
            assertEquals(1, real.syncPage(session, realm, target, 0).result().getAdded());
            assertEquals(1, real.syncPage(session, realm, target, 0).result().getUpdated());
            assertEquals(1, creates.get());
            assertEquals(1, patches.get());
        } finally {
            server.stop(0);
        }
    }

    private UserModel user(String id) {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(id);
        when(user.getUsername()).thenReturn(id);
        when(user.isEnabled()).thenReturn(true);
        return user;
    }

    private void page(int offset, UserModel... page) {
        when(users.searchForUserStream(realm, Map.of(), offset, ScimUserSync.PAGE_SIZE)).thenReturn(Stream.of(page));
    }
}
