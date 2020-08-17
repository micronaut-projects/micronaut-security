package io.micronaut.security.oauth2.endpoint.nonce

import io.micronaut.security.oauth2.ApplicationContextSpecification

class NonceConfigurationSpec extends ApplicationContextSpecification {

    void "Bean of type NonceConfiguration exists by default"() {
        expect:
        applicationContext.containsBean(NonceConfiguration.class)
    }
}
