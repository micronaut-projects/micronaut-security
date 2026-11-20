package io.micronaut.security.token.generator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.BeanContext;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.event.AccessTokenGeneratedEvent;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.render.AccessRefreshToken;
import io.micronaut.security.token.render.TokenRenderer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultAccessRefreshTokenGeneratorTest {

    private static final String EMAIL = "alice@example.com";

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;
    private ApplicationEventPublisher<AccessTokenGeneratedEvent> accessTokenGeneratedEventPublisher;
    private DefaultAccessRefreshTokenGenerator generator;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(DefaultAccessRefreshTokenGenerator.class);
        originalLevel = logger.getLevel();
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        AccessTokenConfiguration accessTokenConfiguration = mock(AccessTokenConfiguration.class);
        when(accessTokenConfiguration.getExpiration()).thenReturn(3600);
        accessTokenGeneratedEventPublisher = mock(ApplicationEventPublisher.class);
        generator = new DefaultAccessRefreshTokenGenerator(
                accessTokenConfiguration,
                mock(TokenRenderer.class),
                new FailingTokenGenerator(),
                mock(BeanContext.class),
                null,
                new CopyingClaimsGenerator(),
                (ApplicationEventPublisher<RefreshTokenGeneratedEvent>) mock(ApplicationEventPublisher.class),
                accessTokenGeneratedEventPublisher);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void tokenGenerationFailureWithNullClaimValueReturnsEmptyAndLogsOnlyClaimNamesAtDebug() {
        logger.setLevel(Level.DEBUG);

        Optional<AccessRefreshToken> result = assertDoesNotThrow(() -> generator.generate("refresh-token", claimsWithNullValue()));

        assertTrue(result.isEmpty(), "no access refresh token is generated when the token generator fails");
        verify(accessTokenGeneratedEventPublisher, never()).publishEvent(any());
        assertEquals(1, appender.list.size(), "exactly one log event is written for the failure");
        ILoggingEvent event = appender.list.get(0);
        assertEquals(Level.DEBUG, event.getLevel(), "the failure is logged at DEBUG");
        assertEquals("tokenGenerator failed to generate access token for claims: [sub, email, nickname]",
                event.getFormattedMessage(),
                "the failure log names the claims and contains none of their values");
    }

    @Test
    void tokenGenerationFailureWithNullClaimValueReturnsEmptyAndLogsNothingAboveDebug() {
        logger.setLevel(Level.INFO);

        Optional<AccessRefreshToken> result = assertDoesNotThrow(() -> generator.generate("refresh-token", claimsWithNullValue()));

        assertTrue(result.isEmpty(), "no access refresh token is generated when the token generator fails");
        verify(accessTokenGeneratedEventPublisher, never()).publishEvent(any());
        assertTrue(appender.list.isEmpty(), "nothing is logged when DEBUG is disabled");
    }

    private static Map<String, Object> claimsWithNullValue() {
        // Insertion order keeps the logged claim names deterministic.
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "alice");
        claims.put("email", EMAIL);
        claims.put("nickname", null);
        return claims;
    }

    private static final class FailingTokenGenerator implements TokenGenerator {
        @Override
        public Optional<String> generateToken(Authentication authentication, Integer expiration) {
            return Optional.empty();
        }

        @Override
        public Optional<String> generateToken(Map<String, Object> claims) {
            return Optional.empty();
        }
    }

    private static final class CopyingClaimsGenerator implements ClaimsGenerator {
        @Override
        public Map<String, Object> generateClaims(Authentication authentication, Integer expiration) {
            return new LinkedHashMap<>(authentication.getAttributes());
        }

        @Override
        public Map<String, Object> generateClaimsSet(Map<String, ?> oldClaims, Integer expiration) {
            return new LinkedHashMap<>(oldClaims);
        }
    }
}
