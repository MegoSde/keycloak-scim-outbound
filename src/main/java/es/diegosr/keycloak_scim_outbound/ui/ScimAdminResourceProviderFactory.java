package es.diegosr.keycloak_scim_outbound.ui;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class ScimAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {
    @Override public String getId() { return "scim-outbound"; }
    @Override public AdminRealmResourceProvider create(KeycloakSession session) {
        return new AdminRealmResourceProvider() {
            @Override public Object getResource(KeycloakSession session, RealmModel realm,
                    AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
                return new ScimAdminResource(realm, auth);
            }
            @Override public void close() { }
        };
    }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
