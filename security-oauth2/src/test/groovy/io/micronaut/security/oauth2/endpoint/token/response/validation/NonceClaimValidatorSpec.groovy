package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.ApplicationContextSpecification

class NonceClaimValidatorSpec extends ApplicationContextSpecification {

    void "NonceClaimsValidator bean exists by default"() {
        expect:
        applicationContext.containsBean(NonceClaimValidator)
    }
}