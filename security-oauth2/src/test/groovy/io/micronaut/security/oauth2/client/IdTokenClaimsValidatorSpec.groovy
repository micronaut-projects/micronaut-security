package io.micronaut.security.oauth2.client

import io.micronaut.security.testutils.ApplicationContextSpecification

class IdTokenClaimsValidatorSpec extends ApplicationContextSpecification {

    void "by default no bean of type IdTokenClaimsValidator exists"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }
}
