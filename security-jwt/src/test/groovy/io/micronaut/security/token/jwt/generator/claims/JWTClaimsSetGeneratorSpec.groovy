package io.micronaut.security.token.jwt.generator.claims

import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.Claims
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification

class JWTClaimsSetGeneratorSpec extends Specification {

    def "generateClaims includes sub and exp claims"() {
        given:
        JWTClaimsSetGenerator generator = new JWTClaimsSetGenerator(new TokenConfiguration() {}, null, null, null)

        when:
        Map<String, Object> claims = generator.generateClaims(Authentication.build('admin', ['ROLE_USER', 'ROLE_ADMIN']), 3600)
        List<String> expectedClaimsNames = [Claims.SUBJECT,
                                            Claims.ISSUED_AT,
                                            Claims.EXPIRATION_TIME,
                                            Claims.NOT_BEFORE,
                                            Claims.ISSUER,
                                            "roles"]
        then:
        claims
        claims.keySet().size() == expectedClaimsNames.size()
        expectedClaimsNames.each { String claimName ->
            assert claims.get(claimName)
        }
    }

    def "generateClaims includes aud claim when ClaimsAudienceProvider bean is present"() {
        given:
        ClaimsAudienceProvider claimsAudienceProvider = { ['https://api.example.com'] }
        JWTClaimsSetGenerator generator = new JWTClaimsSetGenerator(new TokenConfiguration() {}, null, claimsAudienceProvider, null)

        when:
        Map<String, Object> claims = generator.generateClaims(Authentication.build('admin', ['ROLE_USER']), 3600)

        then:
        claims[Claims.AUDIENCE] == ['https://api.example.com']
    }

    def "sub claim is the principal name even if the attributes contain a sub attribute"() {
        given:
        JWTClaimsSetGenerator generator = new JWTClaimsSetGenerator(new TokenConfiguration() {}, null, null, null)
        // e.g. an authentication mapper which qualifies the username with the provider name but retains the raw sub
        Authentication authentication = Authentication.build('provider-a:alice', ['ROLE_USER'], [sub: 'alice', oauth2Provider: 'provider-a'])

        when:
        Map<String, Object> claims = generator.generateClaims(authentication, 3600)

        then:
        claims[Claims.SUBJECT] == 'provider-a:alice'
        claims['oauth2Provider'] == 'provider-a'
    }
}
