package io.micronaut.security.oauth2.openid.endpoints.token

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class TokenEndpointConfigurationDefaultValuesSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    @AutoCleanup
    @Shared
    ApplicationContext context = ApplicationContext.run([
            (SPEC_NAME_PROPERTY): getClass().simpleName,
            'micronaut.security.enabled': true,
    ], Environment.TEST)

    @Shared
    TokenEndpointConfiguration tokenEndpointConfiguration = context.getBean(TokenEndpointConfiguration)

    void "TokenEndpointConfiguration default grant type is authorization_code"() {
        expect:
        tokenEndpointConfiguration.grantType == 'authorization_code'
    }

    void "TokenEndpointConfiguration default authMethod is client_secret_basic"() {
        expect:
        tokenEndpointConfiguration.authMethod == 'client_secret_basic'
    }

}
