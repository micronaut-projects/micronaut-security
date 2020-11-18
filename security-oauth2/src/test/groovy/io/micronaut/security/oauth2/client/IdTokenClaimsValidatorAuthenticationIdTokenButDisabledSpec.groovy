package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.ApplicationContextSpecification

class IdTokenClaimsValidatorAuthenticationIdTokenButDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.token.jwt.claims-validators.openid-idtoken': false
        ]
    }

    void "for idtoken authentication mode a bean of type IdTokenClaimsValidator exists but it can be disabled via micronaut.security.token.jwt.claims-validators.openid-idtoken: false"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }
}
