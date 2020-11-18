package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.ApplicationContextSpecification

class OpenIdIssuerClaimValidatorAuthenticationIdTokenButDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.token.jwt.claims-validators.openid-issuer': false
        ]
    }

    void "for idtoken authentication mode a bean of type OpenIdIssuerClaimValidator exists but it can be disabled via micronaut.security.token.jwt.claims-validators.openid-issuer: false"() {
        expect:
        !applicationContext.containsBean(OpenIdIssuerClaimValidator)
    }
}
