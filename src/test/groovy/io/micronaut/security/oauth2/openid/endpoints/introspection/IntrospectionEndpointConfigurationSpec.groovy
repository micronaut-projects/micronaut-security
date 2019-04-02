package io.micronaut.security.oauth2.openid.endpoints.introspection

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class IntrospectionEndpointConfigurationSpec extends Specification {

    void "A bean IntrospectionEndpointConfiguration is loaded by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(IntrospectionEndpoint)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
