package io.micronaut.security.token.config

import io.micronaut.security.testutils.ApplicationContextSpecification

class TokenConfigurationSpec extends ApplicationContextSpecification {

    void "TokenConfiguration bean exists"() {
        when:
        TokenConfiguration tokenConfiguration = applicationContext.getBean(TokenConfiguration)

        then:
        noExceptionThrown()

        and:
        tokenConfiguration.getNameKey() == 'username'

        and:
        tokenConfiguration.getRolesName() == 'roles'
    }
}
