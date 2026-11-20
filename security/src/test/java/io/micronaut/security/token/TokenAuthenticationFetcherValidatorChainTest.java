package io.micronaut.security.token;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A token accepted by a higher precedence {@link TokenValidator} must never be handed to lower precedence validators,
 * which may be remote (for example the OpenID provider UserInfo endpoint).
 */
@Property(name = "spec.name", value = "TokenAuthenticationFetcherValidatorChainTest")
@MicronautTest
class TokenAuthenticationFetcherValidatorChainTest {

    private static final String ACCEPTED_BY_HIGH_PRECEDENCE = "accepted-by-high-precedence-fixture";
    private static final String ACCEPTED_BY_LOW_PRECEDENCE = "accepted-by-low-precedence-fixture";
    private static final String SLOW_FIRST = "accepted-by-high-precedence-slow-fixture";
    private static final String FAST_SECOND = "accepted-by-high-precedence-fast-fixture";
    private static final String REJECTED = "rejected-by-everyone-fixture";

    @Inject
    TokenAuthenticationFetcher tokenAuthenticationFetcher;

    @Inject
    RecordingLowPrecedenceTokenValidator lowPrecedenceTokenValidator;

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
        assertEquals(List.of(ACCEPTED_BY_LOW_PRECEDENCE), lowPrecedenceTokenValidator.tokens);
    }

    @Test
    void noAuthenticationWhenEveryValidatorRejects() {
        Authentication authentication = fetch(REJECTED);

        assertNull(authentication);
        assertEquals(List.of(REJECTED), lowPrecedenceTokenValidator.tokens);
    }

    @Test
    void multipleTokensAreValidatedOneAtATimeInResolutionOrder() {
        SimpleHttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", null);
        request.getHeaders().add("X-API-KEY", SLOW_FIRST);
        request.getHeaders().add("X-SECOND-API-KEY", FAST_SECOND);

        List<Authentication> authentications = Flux.from(tokenAuthenticationFetcher.fetchAuthentication(request))
            .collectList()
            .block(Duration.ofSeconds(10));

        assertNotNull(authentications);
        assertEquals(List.of("high-" + SLOW_FIRST),
            authentications.stream().map(Authentication::getName).toList(),
            "the first resolved token must be the only one to authenticate, later tokens are not validated");
    }

    @Nullable
    private Authentication fetch(String token) {
        SimpleHttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", null);
        request.getHeaders().add("X-API-KEY", token);
        return Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request))
            .block(Duration.ofSeconds(10));
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherValidatorChainTest")
    @Singleton
    static class ApiKeyTokenReader extends io.micronaut.security.token.reader.HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null;
        }

        @Override
        protected String getHeaderName() {
            return "X-API-KEY";
        }
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherValidatorChainTest")
    @Singleton
    static class SecondApiKeyTokenReader extends io.micronaut.security.token.reader.HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null;
        }

        @Override
        protected String getHeaderName() {
            return "X-SECOND-API-KEY";
        }

        @Override
        public int getOrder() {
            return 10;
        }
    }

    /**
     * Validates asynchronously, as a JWT validator fetching a remote JWKS or executing on the blocking executor does.
     */
    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherValidatorChainTest")
    @Singleton
    static class AsyncHighPrecedenceTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            if (SLOW_FIRST.equals(token) || FAST_SECOND.equals(token)) {
                return Mono.just(Authentication.build("high-" + token))
                    .delayElement(Duration.ofMillis(SLOW_FIRST.equals(token) ? 500 : 0))
                    .subscribeOn(Schedulers.boundedElastic());
            }
            return Mono.fromCallable(() -> ACCEPTED_BY_HIGH_PRECEDENCE.equals(token) ? Authentication.build("high-precedence") : null)
                .delayElement(Duration.ofMillis(200))
                .subscribeOn(Schedulers.boundedElastic());
        }

        @Override
        public int getOrder() {
            return HIGHEST_PRECEDENCE;
        }
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationFetcherValidatorChainTest")
    @Singleton
    static class RecordingLowPrecedenceTokenValidator implements TokenValidator<HttpRequest<?>> {
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
