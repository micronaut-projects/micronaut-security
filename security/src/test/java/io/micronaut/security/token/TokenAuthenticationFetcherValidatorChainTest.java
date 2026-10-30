package io.micronaut.security.token;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.reader.HttpHeaderTokenReader;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A token accepted by a higher precedence {@link TokenValidator} must never be handed to lower precedence validators,
 * which may be remote (for example an OpenID provider endpoint).
 */
class TokenAuthenticationFetcherValidatorChainTest {

    private static final String SPEC_NAME = "TokenAuthenticationFetcherValidatorChainTest";
    private static final String ACCEPTED_BY_HIGH_PRECEDENCE = "accepted-by-high-precedence-fixture";
    private static final String ACCEPTED_BY_LOW_PRECEDENCE = "accepted-by-low-precedence-fixture";
    private static final String REJECTED = "rejected-by-everyone-fixture";

    private static ApplicationContext context;
    private static TokenAuthenticationFetcher tokenAuthenticationFetcher;
    private static RecordingLowPrecedenceTokenValidator lowPrecedenceTokenValidator;

    @BeforeAll
    static void start() {
        context = ApplicationContext.run(Collections.singletonMap("spec.name", SPEC_NAME));
        tokenAuthenticationFetcher = context.getBean(TokenAuthenticationFetcher.class);
        lowPrecedenceTokenValidator = context.getBean(RecordingLowPrecedenceTokenValidator.class);
    }

    @AfterAll
    static void stop() {
        context.close();
    }

    @BeforeEach
    void reset() {
        lowPrecedenceTokenValidator.tokens.clear();
    }

    @Test
    void tokenAcceptedByHigherPrecedenceValidatorIsNotSentToLowerPrecedenceValidators() {
        Authentication authentication = fetch(ACCEPTED_BY_HIGH_PRECEDENCE);

        assertNotNull(authentication);
        assertEquals("high-precedence", authentication.getName());
        assertTrue(lowPrecedenceTokenValidator.tokens.isEmpty(),
            "the token was handed to the lower precedence validator although it had already been accepted");
    }

    @Test
    void lowerPrecedenceValidatorIsConsultedWhenHigherPrecedenceValidatorRejects() {
        Authentication authentication = fetch(ACCEPTED_BY_LOW_PRECEDENCE);

        assertNotNull(authentication);
        assertEquals("low-precedence", authentication.getName());
        assertEquals(Collections.singletonList(ACCEPTED_BY_LOW_PRECEDENCE), lowPrecedenceTokenValidator.tokens);
    }

    @Test
    void noAuthenticationWhenEveryValidatorRejects() {
        Authentication authentication = fetch(REJECTED);

        assertNull(authentication);
        assertEquals(Collections.singletonList(REJECTED), lowPrecedenceTokenValidator.tokens);
    }

    @Nullable
    private static Authentication fetch(String token) {
        SimpleHttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", null);
        request.getHeaders().add("X-API-KEY", token);
        return Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request))
            .block(Duration.ofSeconds(10));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class ApiKeyTokenReader extends HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null;
        }

        @Override
        protected String getHeaderName() {
            return "X-API-KEY";
        }
    }

    /**
     * Validates asynchronously, as a JWT validator fetching a remote JWKS does.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AsyncHighPrecedenceTokenValidator implements TokenValidator {
        @Override
        public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            return Mono.fromCallable(() -> ACCEPTED_BY_HIGH_PRECEDENCE.equals(token) ? Authentication.build("high-precedence") : null)
                .delayElement(Duration.ofMillis(200))
                .subscribeOn(Schedulers.boundedElastic());
        }

        @Override
        public int getOrder() {
            return HIGHEST_PRECEDENCE;
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class RecordingLowPrecedenceTokenValidator implements TokenValidator {
        final List<String> tokens = new CopyOnWriteArrayList<>();

        @Override
        public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            tokens.add(token);
            return ACCEPTED_BY_LOW_PRECEDENCE.equals(token) ? Mono.just(Authentication.build("low-precedence")) : Mono.empty();
        }

        @Override
        public int getOrder() {
            return LOWEST_PRECEDENCE;
        }
    }
}
