package io.micronaut.security.oauth2.openid.endpoints.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.DefaultStateFactory
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateFactory
import spock.lang.Specification

class StateProviderSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "DefaultStateProvider is provided by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        StateFactory provider = context.getBean(StateFactory)

        then:
        provider instanceof DefaultStateFactory

        cleanup:
        context.close()
    }
}
