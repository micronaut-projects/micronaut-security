package io.micronaut.security.oauth2.openid.endpoints.token

import io.micronaut.context.ApplicationContext
import spock.lang.Shared
import spock.lang.Specification

class TokenEndpointConfigurationDefaultValuesSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    Map<String, Object> conf = [
        (SPEC_NAME_PROPERTY): getClass().simpleName,
        'micronaut.security.enabled': true,
    ]

    void "TokenEndpointConfiguration default grant type is authorization_code"() {
        given:
        ApplicationContext context = ApplicationContext.run(conf)

        when:
        TokenEndpoint tokenEndpointConfiguration = context.getBean(TokenEndpoint)

        then:
        noExceptionThrown()
        tokenEndpointConfiguration.grantType == 'authorization_code'

        and:
        !tokenEndpointConfiguration.authMethod

        then:
        context.close()
    }

    void "TokenEndpointConfiguration default authMethod is client_secret_basic if cognito"() {
        given:
        Map<String, Object> specConf = new HashMap<>(conf)
        specConf.put('micronaut.security.oauth2.issuer', 'https://cognito-idp.eu-west-1.amazonaws.com/XXXXX')
        ApplicationContext context = ApplicationContext.run(specConf)

        when:
        TokenEndpoint tokenEndpointConfiguration = context.getBean(TokenEndpoint)

        then:
        noExceptionThrown()
        tokenEndpointConfiguration.authMethod == 'client_secret_basic'

        then:
        context.close()
    }

}
