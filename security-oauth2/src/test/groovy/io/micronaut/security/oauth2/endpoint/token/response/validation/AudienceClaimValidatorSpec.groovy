package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.ApplicationContextSpecification
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import spock.lang.Unroll

class AudienceClaimValidatorSpec extends ApplicationContextSpecification {

    void "AudienceClaimValidator bean exists"() {
        expect:
        applicationContext.containsBean(AudienceClaimValidator)
    }

    @Unroll("#description")
    void "audience claims validator"(String clientId,
                                     List<String> audience,
                                     String authorizedParty,
                                     boolean expected,
                                     String description) {
        given:
        applicationContext.containsBean(AudienceClaimValidator)
        OauthClientConfiguration oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> clientId
        }
        OpenIdProviderMetadata openIdProviderMetadata = Mock(OpenIdProviderMetadata)
        OpenIdClaims openIdClaims = Stub(OpenIdClaims) {
            getAudience() >> audience
            getAuthorizedParty() >> authorizedParty
        }
        AudienceClaimValidator validator = applicationContext.getBean(AudienceClaimValidator)

        expect:
        expected == validator.validate(openIdClaims, oauthClientConfiguration, openIdProviderMetadata)

        where:
        clientId   | audience            | authorizedParty || expected
        'CLIENTID' | []                  | null            || false
        'CLIENTID' | ['FOO']             | null            || false
        'CLIENTID' | ['CLIENTID']        | null            || true
        'CLIENTID' | ['CLIENTID', 'FOO'] | null            || false
        'CLIENTID' | ['CLIENTID', 'FOO'] | 'YYY'           || true

        description = audience.size() > 1 ? (authorizedParty ? "for multiple audiences, azp claim must be present." : "for multiple audiencies claim if azp is not present validation should fail") : (!audience ? 'if audience is empty validation fails' : (clientId != audience.first() ? 'if audience claim does not match client id validation must fail' : 'if audience claim must match client id'))
    }
}
