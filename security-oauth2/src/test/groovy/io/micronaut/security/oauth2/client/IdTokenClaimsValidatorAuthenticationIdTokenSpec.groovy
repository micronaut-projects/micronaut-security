package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.ApplicationContextSpecification

class IdTokenClaimsValidatorAuthenticationIdTokenSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken'
        ]
    }

    void "for idtoken authentication mode a bean of type IdTokenClaimsValidator exists"() {
        expect:
        applicationContext.containsBean(IdTokenClaimsValidator)
    }
}
