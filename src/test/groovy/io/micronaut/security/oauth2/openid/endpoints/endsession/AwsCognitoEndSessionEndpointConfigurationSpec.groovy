package io.micronaut.security.oauth2.openid.endpoints.endsession

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.openid.providers.AwsCognitoEndSessionEndpointConfiguration
import spock.lang.Specification

class AwsCognitoEndSessionEndpointConfigurationSpec extends Specification {

    def "AwsCognitoEndSessionEndpointConfiguration bean is loaded if micronaut.security.oauth2.issuer contains amazoncognito.com"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.domain-name': 'https://sampleapp.auth.eu-west-1.amazoncognito.com',
                'micronaut.security.oauth2.issuer': 'https://cognito-idp.eu-west-1.amazonaws.com/XXXXX'
        ])

        expect:
        applicationContext.containsBean(AwsCognitoEndSessionEndpointConfiguration)

        cleanup:
        applicationContext.close()
    }

    def "AwsCognitoEndSessionEndpointConfiguration bean is not loaded if micronaut.security.oauth2.issuer does not contains amazoncognito.com"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.domain-name': 'https://sampleapp.auth.eu-west-1.amazoncognito.com',
                'micronaut.security.oauth2.issuer': 'https://auth0.com/XXXXX'
        ])

        expect:
        !applicationContext.containsBean(AwsCognitoEndSessionEndpointConfiguration)

        cleanup:
        applicationContext.close()
    }
}
