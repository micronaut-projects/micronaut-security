package io.micronaut.security.oauth2.client.condition

import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.oauth2.client.DefaultOpenIdClient

class OpenIdClientConditionSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.foo.openid.authorization.url': 'https://appleid.apple.com/auth/authorize',
                'micronaut.security.oauth2.clients.foo.openid.token.url': 'https://appleid.apple.com/auth/token'
        ]
    }

    void "OpenIdClientCondition evaluates to true for openid client with manual token and authorization urls"() {
        expect:
        applicationContext.containsBean(DefaultOpenIdClient)
    }
}
