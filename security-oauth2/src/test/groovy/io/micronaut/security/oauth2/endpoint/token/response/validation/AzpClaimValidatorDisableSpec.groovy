package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.ApplicationContextSpecification

class AzpClaimValidatorDisableSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.getConfiguration()
        m['micronaut.security.oauth2.openid.claims-azp'] = false
        m
    }

    void "AuthorizedPartyClaimValidator bean does not exist if micronaut.security.oauth2.openid.claims-azp=false"() {
        expect:
        !applicationContext.containsBean(AuthorizedPartyClaimValidator)
    }

}
