package io.micronaut.security.oauth2

import io.micronaut.security.authentication.Authentication
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
                'micronaut.security.oauth2.clients.cognito.openid.issuer': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_CZbcc3m1G/'
        ]
    }

    @Subject
    @Shared
    ProviderResolver providerResolver = applicationContext.getBean(ProviderResolver)

    void "provider it is resolve from iss claim"() {
        expect:
        providerResolver.resolveProvider(new Authentication() {
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
}
