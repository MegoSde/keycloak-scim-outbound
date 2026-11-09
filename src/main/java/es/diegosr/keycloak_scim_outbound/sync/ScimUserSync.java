package es.diegosr.keycloak_scim_outbound.sync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.user.SynchronizationResult;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.stream.Stream;

/** Full outbound user sync, independent of event and LDAP pending markers. */
public final class ScimUserSync {
    public static final int PAGE_SIZE = 100;
    private final BiFunction<String, String, ScimClient> clients;

    public ScimUserSync() {
        this(ScimClient::new);
    }

    ScimUserSync(BiFunction<String, String, ScimClient> clients) {
        this.clients = clients;
    }

    public record Page(int scanned, SynchronizationResult result) { }

    /** Called in a separate Keycloak transaction for each bounded page. */
    public Page syncPage(KeycloakSession session, RealmModel realm, ComponentModel target, int first) {
        String base = get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
        String token = get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
        if (base == null || base.isBlank() || token == null || token.isBlank()) {
            throw new IllegalArgumentException("SCIM base URL and token are required");
        }
        List<UserModel> users;
        // Use the aggregated provider: this includes local and federated users, not just
        // users imported locally or carrying a previous event's bookkeeping attributes.
        try (Stream<UserModel> stream = session.users().searchForUserStream(realm, Map.of(), first, PAGE_SIZE)) {
            users = stream.toList();
        }
        ScimClient client = clients.apply(base, token);
        SynchronizationResult result = new SynchronizationResult();
        String filter = get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        for (UserModel user : users) {
            try {
                if (user.getServiceAccountClientLink() != null) continue;
                if (filter != null && !filter.isBlank()) {
                    try (var groups = user.getGroupsStream()) {
                        if (groups.noneMatch(g -> g.getName().equals(filter))) continue;
                    }
                }
                String name = userName(target, user);
                if (name == null || name.isBlank()) {
                    result.increaseFailed();
                    continue;
                }
                Optional<String> id = resolveId(client, user.getId(), name);
                if (id.isPresent()) {
                    if (client.patchUser(id.get(), ScimMapper.buildPatchUser(user, user.getId()))) {
                        result.increaseUpdated();
                    } else {
                        result.increaseFailed();
                    }
                } else if (client.createUser(ScimMapper.buildCreateUser(user, name))) {
                    result.increaseAdded();
                } else {
                    // A competing event/sync may have created the same user after lookup.
                    id = resolveId(client, user.getId(), name);
                    if (id.isPresent() && client.patchUser(id.get(), ScimMapper.buildPatchUser(user, user.getId()))) {
                        result.increaseUpdated();
                    } else {
                        result.increaseFailed();
                    }
                }
            } catch (Exception e) {
                result.increaseFailed();
                // Do not log exception text: HTTP/provider exceptions may include secrets.
                System.err.printf("[keycloak-scim-outbound/FULL-SYNC] Failed user id=%s target=%s (%s)%n",
                        user.getId(), target.getId(), e.getClass().getSimpleName());
            }
        }
        return new Page(users.size(), result);
    }

    private static Optional<String> resolveId(ScimClient client, String externalId, String name) {
        Optional<String> id = client.findUserIdByExternalId(externalId);
        return id.isPresent() ? id : client.findUserIdByUserName(name);
    }

    private static String userName(ComponentModel target, UserModel user) {
        return switch (get(target, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username")) {
            case "email" -> user.getEmail();
            case "attribute" -> {
                String attribute = get(target, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
                yield attribute == null || attribute.isBlank() ? null : user.getFirstAttribute(attribute);
            }
            default -> user.getUsername();
        };
    }

    private static String get(ComponentModel target, String key, String fallback) {
        return ScimTargetProviderFactory.get(target, key, fallback);
    }
}
