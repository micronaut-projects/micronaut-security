package io.micronaut.security.oauth2.endpoint.token.response.validation

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Primary
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Order
import io.micronaut.core.order.Ordered
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono

import java.time.Instant

/**
 * Verifies that a nonce mismatch is reported at WARN level naming the failing validator and the claim names,
 * without writing the ID token or any claim value to the logs.
 */
class OpenIdTokenResponseValidatorNonceMismatchLoggingSpec extends ApplicationContextSpecification {

    private static final String EMAIL = 'john.doe@example.com'
    private static final String ISSUER = 'https://issuer.example.com'
    private static final String CLIENT_ID = 'client-id'

    private static final RSAKey RSA_KEY = new RSAKeyGenerator(2048).keyID('nonce-spec').algorithm(JWSAlgorithm.RS256).generate()

    @Override
    String getSpecName() {
        'OpenIdTokenResponseValidatorNonceMismatchLoggingSpec'
    }

    Logger securityLogger = (Logger) LoggerFactory.getLogger('io.micronaut.security')
    Level previousLevel
    ListAppender<ILoggingEvent> appender

    void setup() {
        previousLevel = securityLogger.level
        securityLogger.level = Level.TRACE
        appender = new ListAppender<>()
        appender.start()
        securityLogger.addAppender(appender)
    }

    void cleanup() {
        securityLogger.detachAppender(appender)
        appender.stop()
        securityLogger.level = previousLevel
    }

    void "nonce mismatch is logged at WARN with claim names only"() {
        given:
        ReactiveOpenIdTokenResponseValidator<JWT> validator = applicationContext.getBean(ReactiveOpenIdTokenResponseValidator)
        // since 5.5.2 the ID token is verified exclusively against the JWKS of the provider
        SignedJWT signedJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_KEY.keyID).build(), new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .subject('sherlock')
                .claim('email', EMAIL)
                .claim('nonce', 'expected-nonce')
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build())
        signedJwt.sign(new RSASSASigner(RSA_KEY))
        String idToken = signedJwt.serialize()
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = idToken
        OauthClientConfiguration clientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> CLIENT_ID
            getName() >> 'myprovider'
        }
        OpenIdProviderMetadata providerMetadata = Stub(OpenIdProviderMetadata) {
            getIssuer() >> ISSUER
            getJwksUri() >> (ISSUER + '/jwks')
        }
        appender.list.clear()

        when:
        Optional<JWT> result = Mono.from(validator.validate(clientConfiguration, providerMetadata, tokenResponse, 'a-different-nonce')).blockOptional()

        then:
        result.isEmpty()

        when:
        List<ILoggingEvent> warnings = appender.list.findAll { it.level == Level.WARN }

        then:
        warnings.size() == 1
        warnings[0].formattedMessage.startsWith('NonceClaimValidator failed for provider [myprovider].')
        warnings[0].formattedMessage.contains('email')
        warnings[0].formattedMessage.contains('nonce')
        !appender.list.any { it.level == Level.ERROR }

        and: 'neither the ID token nor any claim value is logged'
        String[] parts = idToken.split('\\.')
        appender.list.every { ILoggingEvent event ->
            String msg = event.formattedMessage
            !msg.contains(idToken) && !msg.contains(parts[1]) && !msg.contains(EMAIL) && !msg.contains('expected-nonce') && !msg.contains('a-different-nonce')
        }
    }

    @Singleton
    @Primary
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Replaces(DefaultJwkSetFetcher)
    @Requires(property = 'spec.name', value = 'OpenIdTokenResponseValidatorNonceMismatchLoggingSpec')
    static class StaticJwkSetFetcher implements JwkSetFetcher<JWKSet> {

        @Override
        Publisher<JWKSet> fetch(String providerName, String url) {
            Mono.just(new JWKSet(RSA_KEY.toPublicJWK()))
        }

        @Override
        void clearCache(String url) {
        }
    }
}
