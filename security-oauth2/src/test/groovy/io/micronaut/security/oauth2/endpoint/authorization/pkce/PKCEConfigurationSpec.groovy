package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEConfigurationSpec extends ApplicationContextSpecification {

    void "Bean of type NonceConfiguration exists by default"() {
        when:
        DefaultPKCEConfiguration defaultPKCEConfiguration = applicationContext.getBean(DefaultPKCEConfiguration.class)

        then:
        noExceptionThrown()

        and: 'default persistence is cookie'
        defaultPKCEConfiguration.getPersistence().get() == 'cookie'
    }
}
