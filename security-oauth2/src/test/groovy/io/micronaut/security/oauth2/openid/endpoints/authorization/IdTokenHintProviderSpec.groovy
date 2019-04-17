package io.micronaut.security.oauth2.openid.endpoints.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification

class IdTokenHintProviderSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "no IdTokenHintProvider is provided by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(IdTokenHintProvider)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }
}
