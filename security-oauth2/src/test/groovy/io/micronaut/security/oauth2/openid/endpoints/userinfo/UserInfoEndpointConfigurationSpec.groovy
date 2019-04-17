package io.micronaut.security.oauth2.openid.endpoints.userinfo

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class UserInfoEndpointConfigurationSpec extends Specification {

    void "A bean UserInfoEndpointConfiguration is loaded by default"() {
        given:
        ApplicationContext context = ApplicationContext.run(['micronaut.security.enabled': true,], Environment.TEST)

        when:
        context.getBean(UserInfoEndpoint)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
