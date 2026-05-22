package io.micronaut.security.docs.customauthentication

import groovy.transform.Canonical
import io.micronaut.security.authentication.Authentication
import io.micronaut.serde.annotation.Serdeable

@Canonical
@Serdeable
class AuthenticationWithEmail {
    String username
    String email

    static AuthenticationWithEmail of(Authentication authentication) {
        new AuthenticationWithEmail(authentication.getName(), authentication.getAttributes().get("email")?.toString())
    }
}
