package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class AuthorizedPartyClaimValidatorSpec extends ApplicationContextSpecification {

    @Unroll("azp validation #description for client_id: #clientId and azp claim: #authorizedParty")
    void "azp claims validator"(String clientId, String authorizedParty, boolean expected, String description) {
        when:
        AuthorizedPartyClaimValidator validator = applicationContext.getBean(AuthorizedPartyClaimValidator)

        then: "AuthorizedPartyClaimValidator bean exists"
        noExceptionThrown()

        when:
        OauthClientConfiguration oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> clientId
        }
        OpenIdProviderMetadata openIdProviderMetadata = Mock(OpenIdProviderMetadata)
        OpenIdClaims claims = Stub(OpenIdClaims) {
            getAuthorizedParty() >> authorizedParty
        }

        then:
        expected == validator.validate(claims, oauthClientConfiguration, openIdProviderMetadata)

        where:
        clientId | authorizedParty || expected
        'xxx'    | null            || true
        'xxx'    | 'xxx'           || true
        'xxx'    | 'yyy'           || false

        description = expected ? "is successful" : "fails"
    }
}
