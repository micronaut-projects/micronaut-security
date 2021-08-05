package io.micronaut.security.token.jwt.roles

import groovy.transform.CompileStatic
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.Claims
import io.micronaut.security.token.DefaultRolesFinder
import io.micronaut.security.token.RolesFinder
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import jakarta.inject.Singleton

@CompileStatic
@Requires(property = "spec.name", value = "customclaimsrolesparser")
@Replaces(DefaultRolesFinder.class)
@Singleton
class CustomRolesParser implements RolesFinder {

    private static final String REALM_ACCESS_KEY = "realm_access"
    private static final String ROLES_KEY = "roles"

    @NonNull
    @Override
    List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        if (attributes[REALM_ACCESS_KEY]) {
            if (attributes[REALM_ACCESS_KEY] && attributes[REALM_ACCESS_KEY] instanceof Map) {
                Map realAccessMap = (Map) attributes[REALM_ACCESS_KEY]
                return resolveRoles(realAccessMap)
            }
        }

        List<String> roles = []
        if ( attributes[ROLES_KEY]) {
            Object realAccess = attributes[ROLES_KEY]
            if (realAccess != null) {
                if (realAccess instanceof Iterable) {
                    for (Object o : ((Iterable) realAccess)) {
                        roles << o.toString()
                    }
                } else {
                    roles << realAccess.toString()
                }
            }
        }
        roles
    }
}
