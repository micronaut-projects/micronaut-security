package io.micronaut.security.oauth2.openid.endpoints.token

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class TokenEndpointConfigurationSpec extends Specification {

    void "A bean TokenEndpointConfiguration is loaded by default"() {
        given:
        ApplicationContext context = ApplicationContext.run(['micronaut.security.enabled': true,], Environment.TEST)

        when:
        context.getBean(TokenEndpointConfiguration)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
