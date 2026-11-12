package io.micronaut.security.token.paseto.validator

import dev.paseto.jpaseto.lang.Keys
import io.micronaut.security.token.paseto.config.PublicKeyConfiguration
import io.micronaut.security.token.paseto.config.SharedSecretConfiguration
import spock.lang.Specification

import javax.crypto.SecretKey
import java.security.PublicKey
import java.time.Instant
import java.util.function.Predicate

class PasetoParserFactorySpec extends Specification {

    void "creates parser for shared secret configuration with required claims"() {
        given:
        PasetoParserFactory factory = new PasetoParserFactory()

        expect:
        factory.pasetoParserWithSharedSecretConfiguration(new TestSharedSecretConfiguration())
    }

    void "creates parser for public key configuration with required claims"() {
        given:
        PasetoParserFactory factory = new PasetoParserFactory()

        expect:
        factory.pasetoParserWithPublicKey(new TestPublicKeyConfiguration())
    }

    private static class TestSharedSecretConfiguration implements SharedSecretConfiguration, RequiredClaimsFixture {
        @Override
        SecretKey getSharedSecret() {
            Keys.secretKey()
        }
    }

    private static class TestPublicKeyConfiguration implements PublicKeyConfiguration, RequiredClaimsFixture {
        @Override
        PublicKey getPublicKey() {
            Keys.keyPairFor(dev.paseto.jpaseto.Version.V2).public
        }
    }

    private static trait RequiredClaimsFixture {
        String getRequiredAudience() {
            'audience'
        }

        String getRequiredKeyId() {
            'kid'
        }

        String getRequiredIssuer() {
            'issuer'
        }

        String getRequiredSubject() {
            'subject'
        }

        String getRequiredTokenId() {
            'token-id'
        }

        Instant getRequiredExpiration() {
            Instant.now().plusSeconds(60)
        }

        Instant getRequiredIssuedAt() {
            Instant.now()
        }

        Instant getRequiredNotBefore() {
            Instant.now()
        }

        Map<String, Predicate<Object>> getRequiredClaimsPredicate() {
            [custom: { Object value -> value == 'value' } as Predicate<Object>]
        }

        Map<String, Object> getRequiredClaimsValue() {
            ['custom-value': 'value']
        }

        Map<String, Predicate<Object>> getRequiredFooterPredicate() {
            [footer: { Object value -> value == 'value' } as Predicate<Object>]
        }
    }
}
