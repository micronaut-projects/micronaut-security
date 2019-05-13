package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.ApplicationContextSpecification

class AudienceClaimValidatorDisableSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.getConfiguration()
        m['micronaut.security.oauth2.openid.claims-validator.audience'] = false
        m
    }

    void "AudienceClaimValidator bean does not exist if micronaut.security.oauth2.openid.claims-validator.audience=false"() {
        expect:
        !applicationContext.containsBean(AudienceClaimValidator)
    }

}
