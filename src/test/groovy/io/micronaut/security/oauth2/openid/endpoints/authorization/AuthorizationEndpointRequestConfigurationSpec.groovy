package io.micronaut.security.oauth2.openid.endpoints.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AuthorizationEndpointRequestConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    @AutoCleanup
    @Shared
    ApplicationContext context = ApplicationContext.run([
            (SPEC_NAME_PROPERTY): getClass().simpleName,
            'micronaut.security.enabled': true,
    ], Environment.TEST)

    @Shared
    AuthorizationEndpointRequestConfiguration authorizationEndpointRequestConfiguration = context.getBean(AuthorizationEndpointRequestConfiguration)


    void "AuthorizationEndpointRequestConfiguration default response mode is query"() {
        expect:
        authorizationEndpointRequestConfiguration.responseMode == 'query'
    }

    void "AuthorizationEndpointRequestConfiguration default response type is code"() {
        expect:
        authorizationEndpointRequestConfiguration.responseType == 'code'
    }

    void "AuthorizationEndpointRequestConfiguration default scopes are [openid]"() {
        expect:
        authorizationEndpointRequestConfiguration.scopes == ['openid']
    }
}
