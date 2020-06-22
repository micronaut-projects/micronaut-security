package io.micronaut.security.oauth2

import org.spockframework.runtime.extension.AbstractGlobalExtension

class KeycloakCleanup extends AbstractGlobalExtension {

    @Override
    void stop() {
        Keycloak.destroy(Keycloak.keycloak)
    }
}
