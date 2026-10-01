package io.micronaut.security.ldap

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.convert.value.ConvertibleValues
import io.micronaut.security.authentication.AuthenticationResponse
import jakarta.inject.Singleton

/**
 * Test-only mapper that copies every LDAP attribute of the user into the Authentication attributes,
 * so that specs can assert which attributes the search returned.
 */
@Requires(property = "spec.name", value = "LdapSearchExcludedAttributesSpec")
@Replaces(DefaultContextAuthenticationMapper)
@Singleton
class AttributesExposingContextAuthenticationMapper implements ContextAuthenticationMapper {

    @Override
    AuthenticationResponse map(ConvertibleValues<Object> attributes, String username, Set<String> groups) {
        Map<String, Object> attrs = [:]
        for (String name : attributes.names()) {
            attrs[name] = attributes.getValue(name)
        }
        AuthenticationResponse.success(username, groups, attrs)
    }
}
