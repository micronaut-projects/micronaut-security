package io.micronaut.security.oauth2.bearer;

import javax.inject.Singleton;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static io.micronaut.security.oauth2.bearer.IntrospectedToken.createActiveAuthentication;
import static io.micronaut.security.oauth2.bearer.IntrospectedToken.createInactiveAuthentication;

/**
 * Implements token introspection handling defined in <a href="https://tools.ietf.org/html/rfc7662">rfc7662</a>.
 * <p>
 * Token considered valid if the introspection response has <code>"active"="true"</code> parameter
 */
@Singleton
public class DefaultTokenIntrospectionHandler implements TokenIntrospectionHandler {

    @Override
    public IntrospectedToken handle(Map<String, Object> tokenIntrospection) {
        boolean isActive = (Boolean) tokenIntrospection.get("active");
        List<String> roles = Optional.ofNullable(tokenIntrospection.get("scope"))
                .map(scopes -> ((String)scopes).trim().split("\\s+"))
                .map(Arrays::asList)
                .orElse(Collections.emptyList());
        String username = Objects.toString(tokenIntrospection.get("username"), "unknown");
        Integer issuingTimestamp = Optional.ofNullable((Integer)tokenIntrospection.get("iat")).orElse(0);
        Integer expirationTimestamp = Optional.ofNullable((Integer)tokenIntrospection.get("exp")).orElse(0);

        return isActive
                ? createActiveAuthentication(username, roles, issuingTimestamp, expirationTimestamp, tokenIntrospection)
                : createInactiveAuthentication();
    }
}
