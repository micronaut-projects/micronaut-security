package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.testutils.ApplicationContextSpecification

class NonceClaimValidatorDisableSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.token.jwt.claims-validators.nonce': false]
    }

    void "NonceClaimsValidator can be disabled with micronaut.security.token.jwt.claims-validators.nonce.enabled"() {
        expect:
        !applicationContext.containsBean(NonceClaimValidator)
    }
}