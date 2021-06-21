package io.micronaut.security.oauth2.endpoint.nonce

import io.micronaut.security.testutils.ApplicationContextSpecification

class NonceConfigurationSpec extends ApplicationContextSpecification {

    void "Bean of type NonceConfiguration exists by default"() {
        when:
        NonceConfiguration nonceConfiguration = applicationContext.getBean(NonceConfiguration.class)

        then:
        noExceptionThrown()

        and: 'default persistence is cookie'
        nonceConfiguration.getPersistence().get() == 'cookie'
    }
}
