package io.micronaut.security.oauth2.openid.endpoints.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.DefaultStateProvider
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateProvider
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
        StateProvider provider = context.getBean(StateProvider)

        then:
        provider instanceof DefaultStateProvider

        cleanup:
        context.close()
    }
}
