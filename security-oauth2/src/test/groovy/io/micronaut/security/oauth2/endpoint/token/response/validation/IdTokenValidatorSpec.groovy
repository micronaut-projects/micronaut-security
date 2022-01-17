package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.client.IdTokenClaimsValidator
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import spock.lang.See
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class IdTokenValidatorSpec extends Specification {

    @See("https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation")
    @Unroll("#description")
    void 'ID Token Claims validation'(String clientId,
                                       String claimIssuer,
                                       String issuer,
                                       String azp,
                                       boolean expected,
                                       String description) {
        given:
        ApplicationContext applicationContext = ApplicationContext.run()
        List<OpenIdClaimsValidator> validators = applicationContext.getBeansOfType(OpenIdClaimsValidator)

        expect:
        validators

        when:
        OauthClientConfiguration oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> clientId
        }
        OpenIdProviderMetadata openIdProviderMetadata = Stub(OpenIdProviderMetadata) {
            getIssuer() >> issuer
        }
        OpenIdClaims claims = Stub(OpenIdClaims) {
            getIssuer() >> claimIssuer
            getAudience() >> aud
            getAuthorizedParty() >> azp
        }
        then:
        expected == validators.stream()
                .allMatch(it -> it.validate(claims, oauthClientConfiguration, openIdProviderMetadata))

        cleanup:
        applicationContext.close()

        where:
        clientId | claimIssuer | aud             | issuer           | azp   |  expected | description
        'xxx'    | 'iss'       | ['xxx']         | 'iss'            | null  | true      | 'id token valid with null azp'
        'xxx'    | 'iss'       | ['xxx', 'foo']  | 'iss'            | 'xxx' | true      | 'id token valid'
        'xxx'    | 'iss'       | ['xxx', 'foo']  | 'iss'            | null  | false     | 'If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.'
        'xxx'    | 'iss'       | ['ooo', 'foo']  | 'iss'            | 'xxx' | false     | 'The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience'
        'xxx'    | null        | ['xxx', 'foo']  | 'iss'            | 'xxx' | false     | 'issuer claim not found'
        'xxx'    | 'foo'       | ['xxx', 'foo']  | 'iss'            | 'xxx' | false     | 'The Issuer Identifier for the OpenID Provider MUST exactly match the value of the iss (issuer) Claim'
        'xxx'    | 'iss'       | ['xxx', 'foo']  | 'iss'            | 'ooo' | false     | 'If an azp Claim is present, the Client SHOULD verify that its client_id is the Claim Value'
    }
}
