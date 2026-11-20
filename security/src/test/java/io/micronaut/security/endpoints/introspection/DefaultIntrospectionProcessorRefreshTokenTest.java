package io.micronaut.security.endpoints.introspection;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.errors.IssuingAnAccessTokenErrorCode;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.security.token.validator.TokenValidator;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultIntrospectionProcessorRefreshTokenTest {

    private static final String SIGNED_A = "signed.key-a";
    private static final String SIGNED_B = "signed.key-b";

    @Test
    void refreshTokenKnownToPersistenceIsActiveAndPopulatedFromThePersistedAuthentication() {
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice", List.of("ROLE_USER"))));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        IntrospectionResponse response = introspect(processor, SIGNED_A);

        assertTrue(response.isActive());
        assertEquals("alice", response.getUsername());
        assertEquals("alice", response.getSub());
        assertEquals(List.of("ROLE_USER"), response.getExtensions().get("roles"));
        assertEquals(List.of("key-a"), persistence.lookups);
    }

    @Test
    void refreshTokenUnknownToPersistenceIsInactiveEvenThoughItsSignatureIsValid() {
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        IntrospectionResponse response = introspect(processor, SIGNED_B);

        assertInactiveAndEmpty(response);
        assertEquals(List.of("key-b"), persistence.lookups);
    }

    @Test
    void refreshTokenIsInactiveWhenPersistenceThrowsInsteadOfEmittingAnError() {
        RefreshTokenPersistence persistence = new NonPersistingRefreshTokenPersistence() {
            @Override
            public Publisher<Authentication> getAuthentication(String refreshToken) {
                throw new IllegalStateException("database down");
            }
        };
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        List<ILoggingEvent> events = captureLogs(Level.WARN, () -> assertInactiveAndEmpty(introspect(processor, SIGNED_A)));

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertTrue(events.get(0).getFormattedMessage().contains("database down"));
        assertNull(events.get(0).getThrowableProxy());
    }

    @Test
    void withoutARefreshTokenValidatorPersistenceIsNeverConsultedAndTheTokenIsInactive() {
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), null, persistence);

        assertInactiveAndEmpty(introspect(processor, SIGNED_A));
        assertTrue(persistence.lookups.isEmpty());
    }

    @Test
    @SuppressWarnings("removal")
    void deprecatedConstructorKeepsTheBehaviourWithoutPersistence() {
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>(List.of(), new TokenConfigurationProperties(), new PrefixRefreshTokenValidator());

        IntrospectionResponse response = introspect(processor, SIGNED_A);

        assertTrue(response.isActive());
        assertNull(response.getUsername());
        assertInactiveAndEmpty(introspect(processor, "tampered.key-a"));
    }

    @Test
    @SuppressWarnings("removal")
    void withoutPersistenceARejectedRefreshTokenUsesTheOverridableInactiveResponse() {
        IntrospectionResponse customInactive = new IntrospectionResponse(false, "custom", null, null, null, null, null, null, null, null, null, null, null);
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>(List.of(), new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), null) {
            @Override
            protected IntrospectionResponse inactiveIntrospectionResponse() {
                return customInactive;
            }
        };

        assertSame(customInactive, introspect(processor, "tampered.key-a"));
    }

    @Test
    void refreshTokenIsInactiveAndLoggedAtWarnWithItsCauseWhenPersistenceEmitsAnError() {
        RefreshTokenPersistence persistence = new NonPersistingRefreshTokenPersistence() {
            @Override
            public Publisher<Authentication> getAuthentication(String refreshToken) {
                return Mono.error(new IllegalStateException("database down"));
            }
        };
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        List<ILoggingEvent> events = captureLogs(() -> assertInactiveAndEmpty(introspect(processor, SIGNED_A)));

        // The WARN line names the cause without a stack trace; the stack trace is only logged at DEBUG.
        assertEquals(2, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertTrue(events.get(0).getFormattedMessage().contains("database down"));
        assertNull(events.get(0).getThrowableProxy());
        assertEquals(Level.DEBUG, events.get(1).getLevel());
        assertEquals("database down", events.get(1).getThrowableProxy().getMessage());
    }

    @Test
    void failureMappingThePersistedAuthenticationIsPropagatedAndNotLoggedAsAPersistenceFailure() {
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>(List.of(), new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), persistence) {
            @Override
            protected Map<String, Object> resolveExtensions(Authentication authentication) {
                throw new IllegalStateException("mapping bug");
            }
        };

        List<ILoggingEvent> events = captureLogs(() -> {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> Mono.from(processor.introspect(new IntrospectionRequest(SIGNED_A, null), HttpRequest.GET("/token_info"))).block());
            assertEquals("mapping bug", e.getMessage());
        });

        assertTrue(events.isEmpty());
    }

    @Test
    void introspectRefreshTokenDoesNoWorkUntilSubscribed() {
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator();
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), refreshTokenValidator, persistence);

        Publisher<IntrospectionResponse> publisher = processor.introspectRefreshToken(SIGNED_A, HttpRequest.GET("/token_info"));

        assertEquals(0, refreshTokenValidator.invocations.get());
        assertTrue(persistence.lookups.isEmpty());
        IntrospectionResponse response = Mono.from(publisher).block();
        assertNotNull(response);
        assertEquals("alice", response.getUsername());
    }

    @Test
    void revocationSignalledWithOauthErrorResponseExceptionIsInactiveAndLoggedAtDebugWithoutTheToken() {
        RefreshTokenPersistence persistence = new NonPersistingRefreshTokenPersistence() {
            @Override
            public Publisher<Authentication> getAuthentication(String refreshToken) {
                return Mono.error(new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_GRANT, "refresh token " + refreshToken + " revoked", null));
            }
        };
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        List<ILoggingEvent> events = captureLogs(() -> assertInactiveAndEmpty(introspect(processor, SIGNED_A)));

        assertEquals(1, events.size());
        assertEquals(Level.DEBUG, events.get(0).getLevel());
        assertNull(events.get(0).getThrowableProxy());
        assertFalse(events.get(0).getFormattedMessage().contains("key-a"));
    }

    @Test
    void withoutPersistenceARefreshTokenWithAValidSignatureIsActiveButNoFieldsArePopulated() {
        // There is no revocation point to consult, so the previous behaviour is kept.
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator();
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), refreshTokenValidator, null);

        IntrospectionResponse response = introspect(processor, SIGNED_A);

        assertTrue(response.isActive());
        assertNull(response.getUsername());
        assertNull(response.getSub());
        assertTrue(response.getExtensions().isEmpty());
        assertEquals(1, refreshTokenValidator.invocations.get());
    }

    @Test
    void refreshTokenWithAnInvalidSignatureIsInactiveAndPersistenceIsNeverConsulted() {
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(), new PrefixRefreshTokenValidator(), persistence);

        assertInactiveAndEmpty(introspect(processor, "tampered.key-a"));
        assertTrue(persistence.lookups.isEmpty());
    }

    @Test
    void tokenIsInactiveWhenThereIsNeitherARefreshTokenValidatorNorATokenValidatorAcceptingIt() {
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(new RejectingTokenValidator()), null, null);

        assertInactiveAndEmpty(introspect(processor, SIGNED_A));
    }

    @Test
    void refreshTokenPathIsNotExecutedWhenATokenValidatorAcceptsTheToken() {
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator();
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(new AcceptingTokenValidator()), refreshTokenValidator, persistence);

        IntrospectionResponse response = introspect(processor, SIGNED_A);

        assertTrue(response.isActive());
        assertEquals("access-token-user", response.getUsername());
        assertEquals(0, refreshTokenValidator.invocations.get());
        assertTrue(persistence.lookups.isEmpty());
    }

    @Test
    void refreshTokenPathIsExecutedOnceEveryTokenValidatorEmitsEmpty() {
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator();
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(Map.of("key-a", Authentication.build("alice")));
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = processor(List.of(new RejectingTokenValidator()), refreshTokenValidator, persistence);

        IntrospectionResponse response = introspect(processor, SIGNED_A);

        assertTrue(response.isActive());
        assertEquals("alice", response.getUsername());
        assertEquals(1, refreshTokenValidator.invocations.get());
        assertEquals(List.of("key-a"), persistence.lookups);
    }

    @Test
    @SuppressWarnings("removal")
    void withoutPersistenceASubclassOverridingEmptyIntrospectionResponseIsStillHonoured() {
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>(List.of(), new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), null) {
            @Override
            protected IntrospectionResponse emptyIntrospectionResponse(String token) {
                return createIntrospectionResponse(Authentication.build("from-override"), HttpRequest.GET("/token_info"));
            }
        };

        assertEquals("from-override", introspect(processor, SIGNED_A).getUsername());
    }

    private static DefaultIntrospectionProcessor<HttpRequest<?>> processor(List<TokenValidator<HttpRequest<?>>> tokenValidators,
                                                                            @Nullable RefreshTokenValidator refreshTokenValidator,
                                                                            @Nullable RefreshTokenPersistence persistence) {
        return new DefaultIntrospectionProcessor<>(tokenValidators, new TokenConfigurationProperties(), refreshTokenValidator, persistence);
    }

    private static IntrospectionResponse introspect(DefaultIntrospectionProcessor<HttpRequest<?>> processor, String token) {
        IntrospectionResponse response = Mono.from(processor.introspect(new IntrospectionRequest(token, null), HttpRequest.GET("/token_info"))).block();
        assertNotNull(response);
        return response;
    }

    private static List<ILoggingEvent> captureLogs(Runnable action) {
        return captureLogs(Level.DEBUG, action);
    }

    private static List<ILoggingEvent> captureLogs(Level level, Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(DefaultIntrospectionProcessor.class);
        Level originalLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.setLevel(level);
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
            appender.stop();
            logger.setLevel(originalLevel);
        }
        return appender.list;
    }

    private static void assertInactiveAndEmpty(IntrospectionResponse response) {
        assertFalse(response.isActive());
        assertNull(response.getUsername());
        assertNull(response.getSub());
        assertTrue(response.getExtensions().isEmpty());
    }

    /**
     * Stand-in for a signature-only validator such as SignedRefreshTokenGenerator: a token is "validly signed" if it starts
     * with {@code signed.}; the remainder is the key that would be stored in the persistence layer.
     */
    static class PrefixRefreshTokenValidator implements RefreshTokenValidator {

        private static final String PREFIX = "signed.";
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        public Optional<String> validate(String refreshToken) {
            invocations.incrementAndGet();
            return refreshToken.startsWith(PREFIX) ? Optional.of(refreshToken.substring(PREFIX.length())) : Optional.empty();
        }
    }

    /**
     * Resolves an {@link Authentication} by the key the {@link PrefixRefreshTokenValidator} extracts.
     */
    static class MapRefreshTokenPersistence extends NonPersistingRefreshTokenPersistence {

        final List<String> lookups = new ArrayList<>();
        private final Map<String, Authentication> tokens;

        MapRefreshTokenPersistence(Map<String, Authentication> tokens) {
            this.tokens = Map.copyOf(tokens);
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            lookups.add(refreshToken);
            return Mono.justOrEmpty(tokens.get(refreshToken));
        }
    }

    abstract static class NonPersistingRefreshTokenPersistence implements RefreshTokenPersistence {
        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
        }
    }

    static class AcceptingTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            return Mono.just(Authentication.build("access-token-user"));
        }
    }

    static class RejectingTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            return Mono.empty();
        }
    }
}
