package io.micronaut.security.token.paseto.generator.claims

import dev.paseto.jpaseto.Claims
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification

import java.time.Instant

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

    def "generateClaims includes configured audience token id and roles key"() {
        given:
        TokenConfiguration tokenConfiguration = new TokenConfiguration() {
            @Override
            String getRolesName() {
                'authorities'
            }
        }
        PasetoClaimsGenerator generator = new PasetoClaimsGenerator(
                tokenConfiguration,
                { 'api' } as ClaimsAudienceProvider,
                { 'generated-id' } as PasetoIdGenerator,
                null)

        when:
        Map<String, Object> claims = generator.generateClaims(Authentication.build('admin', ['ROLE_USER']), null)

        then:
        claims[Claims.AUDIENCE] == 'api'
        claims[Claims.TOKEN_ID] == 'generated-id'
        claims.rolesKey == 'authorities'
        claims.authorities as List == ['ROLE_USER']
        !claims.containsKey(Claims.EXPIRATION)
    }

    def "generateClaimsSet preserves custom claims and refreshes time claims"() {
        given:
        PasetoClaimsGenerator generator = new PasetoClaimsGenerator(new TokenConfiguration() {}, null, null, null)
        Map<String, Object> oldClaims = [
                (io.micronaut.security.token.Claims.EXPIRATION_TIME): Instant.EPOCH,
                (io.micronaut.security.token.Claims.ISSUED_AT): Instant.EPOCH,
                (io.micronaut.security.token.Claims.NOT_BEFORE): Instant.EPOCH,
                custom: 'value'
        ]

        when:
        Map<String, Object> claims = generator.generateClaimsSet(oldClaims, 60)

        then:
        claims.custom == 'value'
        claims[Claims.EXPIRATION] instanceof Instant
        claims[Claims.ISSUED_AT] instanceof Instant
        claims[Claims.NOT_BEFORE] instanceof Instant
        claims[Claims.ISSUED_AT] != Instant.EPOCH
    }

    def "claims set reads not before as instant epoch seconds or empty"() {
        expect:
        new PasetoClaimsSet.Builder().notBefore(Instant.EPOCH).build().notBeforeTime == Instant.EPOCH
        new PasetoClaimsSet.Builder().claim(Claims.NOT_BEFORE, 1L).build().notBeforeTime == Instant.ofEpochSecond(1)
        new PasetoClaimsSet.Builder().claim(Claims.NOT_BEFORE, 'soon').build().notBeforeTime == null
        new PasetoClaimsSet.Builder().build().notBeforeTime == null
    }
}
