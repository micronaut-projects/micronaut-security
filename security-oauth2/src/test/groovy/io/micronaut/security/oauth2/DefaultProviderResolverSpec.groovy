package io.micronaut.security.oauth2

import io.micronaut.core.annotation.NonNull
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class DefaultProviderResolverSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'DefaultProviderResolverSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.oauth2.clients.cognito.client-id': 'XXX',
                'micronaut.security.oauth2.clients.cognito.client-secret': 'XXX',
                'micronaut.security.oauth2.clients.cognito.openid.issuer': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_CZbcc3m1G/',
                'micronaut.security.oauth2.clients.keycloak.client-id': 'XXX',
                'micronaut.security.oauth2.clients.keycloak.client-secret': 'XXX',
                'micronaut.security.oauth2.clients.keycloak.openid.issuer': 'http://keycloak:8080/realms/app',
                'micronaut.security.oauth2.clients.keycloak.openid.issuer-identifier': 'https://sso.example.com/realms/app'
        ]
    }

    @Subject
    @Shared
    ProviderResolver providerResolver = applicationContext.getBean(ProviderResolver)

    void "provider it is resolve from iss claim"() {
        expect:
        providerResolver.resolveProvider(new Authentication() {
            @NonNull
            @Override
            Map<String, Object> getAttributes() {
                ['iss': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_CZbcc3m1G']
            }

            @Override
            String getName() {
                return null
            }
        }).get() == 'cognito'

    }

    void "provider is resolved from the iss claim via the issuer identifier when it differs from the issuer"() {
        expect:
        providerResolver.resolveProvider(authentication('https://sso.example.com/realms/app')).get() == 'keycloak'

        and: 'the URL used to fetch the discovery document is not an accepted iss'
        !providerResolver.resolveProvider(authentication('http://keycloak:8080/realms/app')).isPresent()
        !providerResolver.resolveProvider(authentication('https://sso.example.com/realms/other')).isPresent()
    }

    private static Authentication authentication(String iss) {
        new Authentication() {
            @NonNull
            @Override
            Map<String, Object> getAttributes() {
                ['iss': iss]
            }

            @Override
            String getName() {
                return null
            }
        }
    }
}
