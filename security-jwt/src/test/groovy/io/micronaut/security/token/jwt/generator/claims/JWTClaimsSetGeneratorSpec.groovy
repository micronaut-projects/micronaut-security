package io.micronaut.security.token.jwt.generator.claims

import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification

class JWTClaimsSetGeneratorSpec extends Specification {

    def "generateClaims includes sub and exp claims"() {
        given:
        JWTClaimsSetGenerator generator = new JWTClaimsSetGenerator(null, null, null, null)

        when:
        Map<String, Object> claims = generator.generateClaims(Authentication.build('admin', ['ROLE_USER', 'ROLE_ADMIN'], new TokenConfiguration() {}), 3600)
        List<String> expectedClaimsNames = [JwtClaims.SUBJECT,
                                           JwtClaims.ISSUED_AT,
                                           JwtClaims.EXPIRATION_TIME,
                                           JwtClaims.NOT_BEFORE,
                                            JwtClaims.ISSUER,
                                           "roles"]
        then:
        claims
        claims.keySet().size() == expectedClaimsNames.size()
        expectedClaimsNames.each { String claimName ->
            assert claims.get(claimName)
        }
    }
}
