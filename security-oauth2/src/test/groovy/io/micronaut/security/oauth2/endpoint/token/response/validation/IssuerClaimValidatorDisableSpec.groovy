package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.ApplicationContextSpecification

class IssuerClaimValidatorDisableSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.getConfiguration()
        m['micronaut.security.oauth2.openid.claims-issuer'] = false
        m
    }

    void "AudienceClaimValidator bean does not exist if micronaut.security.oauth2.openid.claims-issuer=false"() {
        expect:
        !applicationContext.containsBean(IssuerClaimValidator)
    }

}
