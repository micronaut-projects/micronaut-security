package io.micronaut.security.ldap;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NullMarked;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Copies every LDAP user attribute into the authentication so tests can inspect the search result.
 */
@Requires(property = "spec.name", value = "LdapSearchExcludedAttributesTest")
@Replaces(DefaultContextAuthenticationMapper.class)
@Singleton
@NullMarked
class AttributesExposingContextAuthenticationMapper implements ContextAuthenticationMapper {

    @Override
    public AuthenticationResponse map(ConvertibleValues<Object> attributes, String username, Set<String> groups) {
        Map<String, Object> authenticationAttributes = new HashMap<>();
        for (String name : attributes.names()) {
            authenticationAttributes.put(name, attributes.getValue(name));
        }
        return AuthenticationResponse.success(username, groups, authenticationAttributes);
    }
}
