package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.fgap.RealmPermissionEvaluator;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScimAdminResourceTest {
    private final RealmModel realm = mock(RealmModel.class);
    private final AdminPermissionEvaluator auth = mock(AdminPermissionEvaluator.class);
    private final RealmPermissionEvaluator permissions = mock(RealmPermissionEvaluator.class);

    private ComponentModel target() {
        when(auth.realm()).thenReturn(permissions);
        when(realm.getId()).thenReturn("realm");
        var target = new ComponentModel();
        target.setId("target"); target.setParentId("realm");
        target.setProviderId(ScimTargetProviderFactory.ID);
        target.setProviderType("org.keycloak.storage.UserStorageProvider");
        target.getConfig().putSingle("baseUrl", "https://saved.example/scim/v2");
        target.getConfig().putSingle("token", "saved-secret-token");
        when(realm.getComponent("target")).thenReturn(target);
        return target;
    }

    @Test void requiresManageRealmBeforeReadingConfiguration() {
        target();
        doThrow(new ForbiddenException()).when(permissions).requireManageRealm();
        var resource = new ScimAdminResource(realm, auth, t -> { fail("No network calls allowed"); return null; });
        assertThrows(ForbiddenException.class, () -> resource.testConnection("target"));
        verify(realm, never()).getComponent(anyString());
    }

    @Test void rejectsMissingOtherProviderAndOtherRealmComponents() {
        var target = target();
        var resource = new ScimAdminResource(realm, auth, t -> { fail("No network calls allowed"); return null; });
        assertThrows(NotFoundException.class, () -> resource.testConnection("missing"));
        target.setProviderId("ldap");
        assertThrows(NotFoundException.class, () -> resource.testConnection("target"));
        target.setProviderId(ScimTargetProviderFactory.ID); target.setParentId("other-realm");
        assertThrows(NotFoundException.class, () -> resource.testConnection("target"));
    }

    @Test void usesSavedConfigurationAndDoesNotReturnSecrets() {
        var target = target(); var client = mock(ScimClient.class);
        var result = new ScimClient.ConnectionTestResult(true, "OK", "Connection successful", 200);
        when(client.testConnection()).thenReturn(result);
        var resource = new ScimAdminResource(realm, auth, t -> { assertSame(target, t); return client; });
        try (var response = resource.testConnection("target")) {
            assertSame(result, response.getEntity());
            assertEquals("no-store", response.getHeaderString("Cache-Control"));
        }
        verify(client).testConnection();
        verifyNoMoreInteractions(client);
    }

    @Test void invalidCertificateAndIncompleteConfigProduceSafeErrors() {
        var target = target();
        var resource = new ScimAdminResource(realm, auth, t -> { throw new IllegalArgumentException("do not expose this"); });
        try (var response = resource.testConnection("target")) {
            var result = (ScimClient.ConnectionTestResult) response.getEntity();
            assertFalse(result.success()); assertEquals("INVALID_CONFIGURATION", result.code());
            assertFalse(result.message().contains("do not expose"));
        }
        target.getConfig().remove("token");
        try (var response = resource.testConnection("target")) {
            var result = (ScimClient.ConnectionTestResult) response.getEntity();
            assertFalse(result.success()); assertTrue(result.message().contains("token"));
        }
    }
}
