package io.micronaut.security.oauth2.bearer;

import io.micronaut.security.authentication.Authentication;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents introspection information of oauth token received from authorization service.
 *
 * @author svishnyakoff
 */
public class IntrospectedToken implements Authentication {

    private static final IntrospectedToken INACTIVE_TOKEN = new IntrospectedToken(false, "", Collections.emptyList(), Collections.emptyMap());
    private final boolean isActive;
    private final String username;
    private final Map<String, Object> attributes;

    private IntrospectedToken(boolean isActive, String username, List<String> scopes, Map<String, Object> attributes){
        this.isActive = isActive;
        this.username = username;

        Map<String, Object> attr = new HashMap<>();
        attr.putAll(attributes);
        attr.put("roles", scopes);
        this.attributes = Collections.unmodifiableMap(attr);
    }


    /**
     * Create valid active token.
     *
     * @param username   username associated with token
     * @param attributes token introspection attributes
     * @return Active token
     */
    public static IntrospectedToken createActiveAuthentication(String username, List<String> scopes, Map<String, Object> attributes) {
        return new IntrospectedToken(true, username, scopes, attributes);
    }

    /**
     * @return inactive token.
     */
    public static IntrospectedToken createInactiveAuthentication() {
        return INACTIVE_TOKEN;
    }

    @Nonnull
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return username;
    }

    /**
     * @return true if token is valid and considered valid by authorization service. False otherwise, e.g. token expired,
     * token is not recognized by authorization service, request to auth service failed.
     */
    public boolean isActive() {
        return isActive;
    }
}
