package io.micronaut.security.oauth2.endpoint.token.response.validation;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Order;
import io.micronaut.core.order.Ordered;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A nonce mismatch is reported at WARN level naming the failing validator and the claim names, without writing the
 * ID token or any claim value to the logs.
 */
@Property(name = "spec.name", value = OpenIdTokenResponseValidatorNonceMismatchLoggingTest.SPEC_NAME)
@MicronautTest(startApplication = false)
class OpenIdTokenResponseValidatorNonceMismatchLoggingTest {

    static final String SPEC_NAME = "OpenIdTokenResponseValidatorNonceMismatchLoggingTest";

    private static final String EMAIL = "john.doe@example.com";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String CLIENT_ID = "client-id";
    private static final String NONCE_CLAIM = "expected-nonce";
    private static final String PERSISTED_NONCE = "a-different-nonce";
    private static final RSAKey RSA_KEY = generateKey();

    @Inject
    ReactiveOpenIdTokenResponseValidator<JWT> validator;

    private Logger securityLogger;
    private Level previousLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLogs() {
        securityLogger = (Logger) LoggerFactory.getLogger("io.micronaut.security");
        previousLevel = securityLogger.getLevel();
        securityLogger.setLevel(Level.TRACE);
        appender = new ListAppender<>();
        appender.start();
        securityLogger.addAppender(appender);
    }

    @AfterEach
    void restoreLogs() {
        securityLogger.detachAppender(appender);
        appender.stop();
        securityLogger.setLevel(previousLevel);
    }

    @Test
    void nonceMismatchIsLoggedAtWarnWithClaimNamesOnly() throws Exception {
        // the ID token is verified exclusively against the JWKS of the provider
        SignedJWT signedJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_KEY.getKeyID()).build(), new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .subject("sherlock")
                .claim("email", EMAIL)
                .claim("nonce", NONCE_CLAIM)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build());
        signedJwt.sign(new RSASSASigner(RSA_KEY));
        String idToken = signedJwt.serialize();
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse();
        tokenResponse.setIdToken(idToken);
        OauthClientConfiguration clientConfiguration = mock(OauthClientConfiguration.class);
        when(clientConfiguration.getClientId()).thenReturn(CLIENT_ID);
        when(clientConfiguration.getName()).thenReturn("myprovider");
        OpenIdProviderMetadata providerMetadata = mock(OpenIdProviderMetadata.class);
        when(providerMetadata.getIssuer()).thenReturn(ISSUER);
        when(providerMetadata.getJwksUri()).thenReturn(ISSUER + "/jwks");

        Optional<JWT> result = Mono.from(validator.validate(clientConfiguration, providerMetadata, tokenResponse, PERSISTED_NONCE)).blockOptional();

        assertTrue(result.isEmpty());
        List<ILoggingEvent> warnings = appender.list.stream().filter(event -> event.getLevel() == Level.WARN).toList();
        assertEquals(1, warnings.size(), () -> "expected exactly one warning but got " + warnings);
        String warning = warnings.get(0).getFormattedMessage();
        assertTrue(warning.startsWith("NonceClaimValidator failed for provider [myprovider]. Expected nonce present: true, nonce claim present: true, ID token claims: "), warning);
        assertTrue(warning.contains("email"), warning);
        assertTrue(warning.contains("nonce"), warning);
        assertTrue(appender.list.stream().noneMatch(event -> event.getLevel() == Level.ERROR));
        String payload = idToken.split("\\.")[1];
        for (ILoggingEvent event : appender.list) {
            String message = event.getFormattedMessage();
            assertFalse(message.contains(idToken), () -> "ID token logged: " + message);
            assertFalse(message.contains(payload), () -> "ID token payload logged: " + message);
            assertFalse(message.contains(EMAIL), () -> "claim value logged: " + message);
            assertFalse(message.contains(NONCE_CLAIM), () -> "nonce claim logged: " + message);
            assertFalse(message.contains(PERSISTED_NONCE), () -> "persisted nonce logged: " + message);
        }
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("nonce-test").algorithm(JWSAlgorithm.RS256).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Singleton
    @Primary
    @Order(Ordered.HIGHEST_PRECEDENCE) // the Reactor cache fetcher is @Primary too
    @Replaces(DefaultJwkSetFetcher.class)
    @Requires(property = "spec.name", value = SPEC_NAME)
    static class StaticJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        @Override
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            return Mono.just(new JWKSet(RSA_KEY.toPublicJWK()));
        }

        @Override
        public void clearCache(String url) {
            // nothing is cached
        }
    }
}
