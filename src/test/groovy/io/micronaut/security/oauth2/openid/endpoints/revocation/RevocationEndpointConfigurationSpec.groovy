package io.micronaut.security.oauth2.openid.endpoints.revocation

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class RevocationEndpointConfigurationSpec extends Specification {

    void "A bean RevocationEndpointConfiguration is loaded by default"() {
        given:
        ApplicationContext context = ApplicationContext.run(['micronaut.security.enabled': true,], Environment.TEST)

        when:
        context.getBean(RevocationEndpointConfiguration)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
