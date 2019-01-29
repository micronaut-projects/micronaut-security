package io.micronaut.security.oauth2.openid.endpoints.endsession

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class AwsCognitoEndSessionEndpointConfigurationSpec extends Specification {

    def "AwsCognitoEndSessionEndpointConfiguration bean is loaded if micronaut.security.oauth2.openid-configuration contains amazoncognito.com"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.domain-name': 'https://sampleapp.auth.eu-west-1.amazoncognito.com',
                'micronaut.security.oauth2.openid-configuration': 'https://cognito-idp.eu-west-1.amazonaws.com/XXXXX/.well-known/openid-configuration'
        ])

        expect:
        applicationContext.containsBean(AwsCognitoEndSessionEndpointConfiguration)

        cleanup:
        applicationContext.close()
    }

    def "AwsCognitoEndSessionEndpointConfiguration bean is not loaded if micronaut.security.oauth2.openid-configuration does not contains amazoncognito.com"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.domain-name': 'https://sampleapp.auth.eu-west-1.amazoncognito.com',
                'micronaut.security.oauth2.openid-configuration': 'https://auth0.com/XXXXX/.well-known/openid-configuration'
        ])

        expect:
        !applicationContext.containsBean(AwsCognitoEndSessionEndpointConfiguration)

        cleanup:
        applicationContext.close()
    }
}
