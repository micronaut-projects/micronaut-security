
package io.micronaut.security.token.views

import groovy.transform.CompileStatic
import io.micronaut.security.authentication.UserDetails

@CompileStatic
class UserDetailsEmail extends UserDetails  {
    String email

    UserDetailsEmail(String username, Collection<String> roles, String email) {
        super(username, roles)
        this.email = email
    }

    @Override
    Map<String, Object> getAttributes(String rolesKey, String usernameKey) {
        Map<String, Object> attributes = super.getAttributes(rolesKey, usernameKey)
        attributes.put("email", email)
        attributes
    }

}
