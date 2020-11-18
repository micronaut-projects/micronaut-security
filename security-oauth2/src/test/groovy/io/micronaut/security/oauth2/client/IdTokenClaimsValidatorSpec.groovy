package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.ApplicationContextSpecification

class IdTokenClaimsValidatorSpec extends ApplicationContextSpecification {

    void "by default no bean of type OpenIdIssuerClaimValidator exists"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }
}
