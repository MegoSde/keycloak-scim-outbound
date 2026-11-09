package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import java.util.function.Function;

/** Realm admin extension. Only saved server-side configuration is used. */
public class ScimAdminResource {
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final Function<ComponentModel, ScimClient> clients;

    public ScimAdminResource(RealmModel realm, AdminPermissionEvaluator auth) {
        this(realm, auth, ScimClient::forTarget);
    }

    ScimAdminResource(RealmModel realm, AdminPermissionEvaluator auth, Function<ComponentModel, ScimClient> clients) {
        this.realm = realm;
        this.auth = auth;
        this.clients = clients;
    }

    @POST
    @Path("{componentId}/test-connection")
    @Produces(MediaType.APPLICATION_JSON)
    public Response testConnection(@PathParam("componentId") String componentId) {
        auth.realm().requireManageRealm();
        ComponentModel target = realm.getComponent(componentId);
        if (target == null || !ScimTargetProviderFactory.ID.equals(target.getProviderId())
                || !"org.keycloak.storage.UserStorageProvider".equals(target.getProviderType())
                || !realm.getId().equals(target.getParentId())) throw new NotFoundException();
        ScimClient.ConnectionTestResult result;
        if (ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, "").isBlank()
                || ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, "").isBlank()) {
            result = new ScimClient.ConnectionTestResult(false, "INVALID_CONFIGURATION", "Save a SCIM Base URL and token before testing.", null);
        } else {
            try { result = clients.apply(target).testConnection(); }
            catch (IllegalArgumentException e) {
                result = new ScimClient.ConnectionTestResult(false, "INVALID_CONFIGURATION",
                        "The saved TLS configuration is invalid. Check the uploaded PEM certificates and their validity dates.", null);
            }
        }
        return Response.ok(result).header("Cache-Control", "no-store").build();
    }
}
