package io.micronaut.security.authentication;

import io.micronaut.context.ApplicationContext;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.config.SecurityConfigurationProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@link io.micronaut.security.config.AuthenticationStrategy#ANY} the imperative and the reactive paths of
 * {@link Authenticator} must select the same failure when every provider fails: the failure of the first provider
 * in provider order. A provider throwing a non {@link AuthenticationException} must surface as an
 * {@link AuthenticationFailed} on both paths, never as an error.
 * The first provider is deliberately slow so that provider order, not completion order, decides the failure.
 */
class AuthenticatorAnyStrategyFailureTest {

    private static final Duration SLOW = Duration.ofMillis(200);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static ApplicationContext ctx;

    @BeforeAll
    static void startContext() {
        ctx = ApplicationContext.run();
    }

    @AfterAll
    static void closeContext() {
        ctx.close();
    }

    @ParameterizedTest
    @EnumSource(ProviderType.class)
    void whenEveryProviderFailsTheFirstProviderFailureIsReturned(ProviderType type) {
        Authenticator<Object> authenticator = type.authenticator(
                failing(AuthenticationFailureReason.USER_NOT_FOUND).after(SLOW),
                failing(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH));

        assertFailure(AuthenticationFailureReason.USER_NOT_FOUND, authenticate(authenticator));
    }

    @ParameterizedTest
    @EnumSource(ProviderType.class)
    void whenTheSecondProviderThrowsTheFirstProviderFailureIsReturned(ProviderType type) {
        Authenticator<Object> authenticator = type.authenticator(
                failing(AuthenticationFailureReason.USER_NOT_FOUND).after(SLOW),
                throwing(new RuntimeException("boom")));

        assertFailure(AuthenticationFailureReason.USER_NOT_FOUND, authenticate(authenticator));
    }

    @ParameterizedTest
    @EnumSource(ProviderType.class)
    void whenTheFirstProviderThrowsAnAuthenticationFailedIsReturnedInsteadOfAnError(ProviderType type) {
        Authenticator<Object> authenticator = type.authenticator(
                throwing(new RuntimeException("boom")).after(SLOW),
                failing(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH));

        AuthenticationResponse rsp = authenticate(authenticator);

        assertFailure(AuthenticationFailureReason.CUSTOM, rsp);
        assertEquals("boom", rsp.getMessage().orElse(null));
    }

    @ParameterizedTest
    @EnumSource(ProviderType.class)
    void aLaterSuccessfulProviderStillWins(ProviderType type) {
        Authenticator<Object> authenticator = type.authenticator(
                failing(AuthenticationFailureReason.USER_NOT_FOUND),
                throwing(new RuntimeException("boom")),
                new Outcome(() -> AuthenticationResponse.success("sherlock"), Duration.ZERO));

        AuthenticationResponse rsp = authenticate(authenticator);

        assertTrue(rsp.isAuthenticated());
        assertEquals("sherlock", rsp.getAuthentication().orElseThrow().getName());
    }

    @Test
    void aReactiveProviderThrowingInsteadOfReturningAPublisherIsTreatedAsAFailure() {
        ReactiveAuthenticationProvider<Object, Object, Object> throwsOnCall = (requestContext, authenticationRequest) -> {
            throw new IllegalStateException("boom");
        };
        Authenticator<Object> authenticator = new Authenticator<>(ctx,
                List.of(new ReactiveProvider(failing(AuthenticationFailureReason.USER_NOT_FOUND)), throwsOnCall),
                List.of(),
                new SecurityConfigurationProperties());

        assertFailure(AuthenticationFailureReason.USER_NOT_FOUND, authenticate(authenticator));
    }

    private static AuthenticationResponse authenticate(Authenticator<Object> authenticator) {
        return Mono.from(authenticator.authenticate(null, new UsernamePasswordCredentials("sherlock", "password")))
                .block(TIMEOUT);
    }

    private static void assertFailure(AuthenticationFailureReason expected, AuthenticationResponse rsp) {
        assertEquals(expected, assertInstanceOf(AuthenticationFailed.class, rsp).getReason());
    }

    private static Outcome failing(AuthenticationFailureReason reason) {
        return new Outcome(() -> AuthenticationResponse.failure(reason), Duration.ZERO);
    }

    private static Outcome throwing(RuntimeException e) {
        return new Outcome(() -> {
            throw e;
        }, Duration.ZERO);
    }

    /**
     * What a provider answers, and how long it takes to do so.
     */
    private record Outcome(Supplier<AuthenticationResponse> response, Duration delay) {

        Outcome after(Duration delay) {
            return new Outcome(response, delay);
        }

        AuthenticationResponse blockingResponse() {
            try {
                Thread.sleep(delay.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            return response.get();
        }
    }

    enum ProviderType {
        IMPERATIVE {
            @Override
            Authenticator<Object> authenticator(Outcome... outcomes) {
                return imperative(outcomes, outcome -> (requestContext, authRequest) -> outcome.blockingResponse());
            }
        },
        /**
         * Forces the imperative providers through the reactive path via {@link AuthenticationProviderAdapter}.
         */
        IMPERATIVE_BLOCKING {
            @Override
            Authenticator<Object> authenticator(Outcome... outcomes) {
                return imperative(outcomes, BlockingProvider::new);
            }
        },
        REACTIVE {
            @Override
            Authenticator<Object> authenticator(Outcome... outcomes) {
                List<ReactiveAuthenticationProvider<Object, ?, ?>> providers = List.of(outcomes).stream()
                        .<ReactiveAuthenticationProvider<Object, ?, ?>>map(ReactiveProvider::new)
                        .toList();
                return new Authenticator<>(ctx, providers, List.of(), new SecurityConfigurationProperties());
            }
        };

        abstract Authenticator<Object> authenticator(Outcome... outcomes);

        private static Authenticator<Object> imperative(Outcome[] outcomes,
                                                        Function<Outcome, AuthenticationProvider<Object, ?, ?>> toProvider) {
            List<AuthenticationProvider<Object, ?, ?>> providers = List.of(outcomes).stream().map(toProvider).toList();
            return new Authenticator<>(ctx, List.of(), providers, new SecurityConfigurationProperties());
        }
    }

    private record BlockingProvider(Outcome outcome) implements ExecutorAuthenticationProvider<Object, Object, Object> {
        @Override
        public String getExecutorName() {
            return TaskExecutors.BLOCKING;
        }

        @Override
        public AuthenticationResponse authenticate(Object requestContext, AuthenticationRequest<Object, Object> authRequest) {
            return outcome.blockingResponse();
        }
    }

    private record ReactiveProvider(Outcome outcome) implements ReactiveAuthenticationProvider<Object, Object, Object> {
        @Override
        public Publisher<AuthenticationResponse> authenticate(Object requestContext, AuthenticationRequest<Object, Object> authenticationRequest) {
            return Mono.fromSupplier(outcome.response()).delaySubscription(outcome.delay());
        }
    }
}
