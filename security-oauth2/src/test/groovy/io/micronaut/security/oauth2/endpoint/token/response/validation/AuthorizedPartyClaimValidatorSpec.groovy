package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.testutils.ApplicationContextSpecification

class AuthorizedPartyClaimValidatorSpec extends ApplicationContextSpecification {

    void "AuthorizedPartyClaimValidator bean exists"() {
        expect:
        applicationContext.containsBean(AuthorizedPartyClaimValidator)
    }
}
