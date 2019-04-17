package io.micronaut.security.oauth2.openid.endpoints.endsession

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class EndSessionEndpointConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "A bean EndSessionEndpointConfiguration is loaded by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(EndSessionEndpoint)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
