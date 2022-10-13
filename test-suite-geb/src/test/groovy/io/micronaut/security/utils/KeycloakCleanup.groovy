package io.micronaut.security.utils

import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import org.spockframework.runtime.extension.IGlobalExtension

class KeycloakCleanup implements IGlobalExtension {
    @Override
    void stop() {
        Keycloak.destroy()
    }
}
