package io.micronaut.security.token.jwt.nimbus;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.type.Argument;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.validator.JsonWebTokenSignatureValidator;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Neither the compact serialization of a JWT nor the values of its claims are written to the logs.
 */
class JwtContentsNotLoggedTest {

    private static final String EMAIL = "john.doe@example.com";

    private static ApplicationContext applicationContext;

    private Logger securityLogger;
    private Level previousLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeAll
    static void startContext() {
        applicationContext = ApplicationContext.run(Map.of(
                "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne"));
    }

    @AfterAll
    static void closeContext() {
        applicationContext.close();
    }

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
    void claimsGenerationLogsClaimNamesButNotClaimValues() {
        String token = generateToken();

        assertTrue(messages().stream().anyMatch(message -> message.startsWith("Generated claim set with claims:")
                && message.contains("email") && message.contains("sub")), () -> "claim names not logged: " + messages());
        assertNotLogged(token);
    }

    @Test
    void signatureValidatorDoesNotLogTheTokenWhenVerificationFails() throws Exception {
        JsonWebTokenSignatureValidator<SignedJWT> signatureValidator = applicationContext.getBean(
                Argument.of(JsonWebTokenSignatureValidator.class, SignedJWT.class));
        String token = generateToken();
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + new StringBuilder(parts[2]).reverse();
        appender.list.clear();

        boolean valid = signatureValidator.validateSignature(SignedJWT.parse(tampered));

        assertFalse(valid);
        assertTrue(messages().stream().anyMatch(message -> message.startsWith("Signature verification failed for JWT [kid=")
                && message.contains("alg=HS256")), () -> "verification failure not logged: " + messages());
        assertNotLogged(token);
        assertNotLogged(tampered);
    }

    @Test
    void reactiveJwksSignatureDoesNotLogTheTokenWhetherOrNotVerificationSucceeds() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        RSAKey otherKey = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        ReactiveJwksSignature signature = new ReactiveJwksSignature(new TestJwksSignatureConfiguration(),
                new DefaultJwkValidator(), new StaticJwkSetFetcher(new JWKSet(rsaKey.toPublicJWK())));
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("sherlock").jwtID("jti-123").claim("email", EMAIL).build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-1").build();
        SignedJWT validJwt = new SignedJWT(header, claims);
        validJwt.sign(new RSASSASigner(rsaKey));
        SignedJWT invalidJwt = new SignedJWT(header, claims);
        invalidJwt.sign(new RSASSASigner(otherKey));

        assertEquals(Boolean.TRUE, Mono.from(signature.verify(validJwt)).block());
        assertEquals(Boolean.FALSE, Mono.from(signature.verify(invalidJwt)).block());

        assertTrue(messages().contains("Signature verified for JWT [kid=kid-1, alg=RS256, jti=jti-123]"), () -> messages().toString());
        assertTrue(messages().contains("Signature not verified for JWT [kid=kid-1, alg=RS256, jti=jti-123]"), () -> messages().toString());
        assertNotLogged(validJwt.serialize());
        assertNotLogged(invalidJwt.serialize());
    }

    private static String generateToken() {
        Authentication authentication = Authentication.build("sherlock", List.of("ROLE_DETECTIVE"), Map.of("email", EMAIL));
        return applicationContext.getBean(JwtTokenGenerator.class).generateToken(authentication, 3600).orElseThrow();
    }

    private List<String> messages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void assertNotLogged(String token) {
        String[] parts = token.split("\\.");
        for (String message : messages()) {
            assertFalse(message.contains(token), () -> "token logged: " + message);
            assertFalse(message.contains(parts[1]), () -> "payload logged: " + message);
            assertFalse(message.contains(parts[2]), () -> "signature logged: " + message);
            assertFalse(message.contains(EMAIL), () -> "claim value logged: " + message);
        }
    }

    private static final class TestJwksSignatureConfiguration implements JwksSignatureConfiguration {
        @Override
        public String getUrl() {
            return "http://localhost/.well-known/jwks.json";
        }

        @Override
        public KeyType getKeyType() {
            return KeyType.RSA;
        }

        @Override
        public Integer getCacheExpiration() {
            return 60;
        }

        @Override
        public String getName() {
            return "test";
        }
    }

    private record StaticJwkSetFetcher(JWKSet jwkSet) implements JwkSetFetcher<JWKSet> {
        @Override
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            return Mono.just(jwkSet);
        }

        @Override
        public void clearCache(String url) {
            // nothing is cached
        }
    }
}
