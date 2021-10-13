package io.micronaut.security.token.paseto.generator.claims

import dev.paseto.jpaseto.Claims
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification

class PasetoClaimsGeneratorSpec extends Specification {
    def "generateClaims includes sub and exp claims"() {
        given:
        PasetoClaimsGenerator generator = new PasetoClaimsGenerator(new TokenConfiguration() {}, null, null, null)

        when:
        Map<String, Object> claims = generator.generateClaims(Authentication.build('admin', ['ROLE_USER', 'ROLE_ADMIN']), 3600)
        List<String> expectedClaimsNames = [Claims.SUBJECT,
                                            Claims.ISSUED_AT,
                                            Claims.EXPIRATION,
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
}
