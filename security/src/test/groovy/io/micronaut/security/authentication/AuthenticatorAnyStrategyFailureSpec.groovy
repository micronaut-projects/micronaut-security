package io.micronaut.security.authentication

import io.micronaut.context.ApplicationContext
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.authentication.provider.AuthenticationProvider
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.config.SecurityConfigurationProperties
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.time.Duration

/**
 * With {@link io.micronaut.security.config.AuthenticationStrategy#ANY} the imperative and the reactive paths of
 * {@link Authenticator} must select the same failure when every provider fails: the failure of the first provider
 * in provider order. A provider throwing a non {@link AuthenticationException} must surface as an
 * {@link AuthenticationFailed} on both paths, never as an error.
 * The first provider is deliberately slow so that provider order, not completion order, decides the failure.
 */
class AuthenticatorAnyStrategyFailureSpec extends Specification {

    static final String IMPERATIVE = 'imperative'
    static final String IMPERATIVE_BLOCKING = 'imperative blocking'
    static final String REACTIVE = 'reactive'
    static final long SLOW_MILLIS = 200

    @Shared
    @AutoCleanup
    ApplicationContext ctx = ApplicationContext.run()

    @Unroll
    void "#type providers: when every provider fails, the first provider failure is returned"(String type) {
        given:
        Authenticator authenticator = authenticator(type, [
                failing(type, AuthenticationFailureReason.USER_NOT_FOUND, SLOW_MILLIS),
                failing(type, AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
        ])

        when:
        AuthenticationResponse rsp = Mono.from(authenticator.authenticate(null, credentials())).block()

        then:
        rsp instanceof AuthenticationFailed
        ((AuthenticationFailed) rsp).reason == AuthenticationFailureReason.USER_NOT_FOUND

        where:
        type << [IMPERATIVE, IMPERATIVE_BLOCKING, REACTIVE]
    }

    @Unroll
    void "#type providers: when the second provider throws, the first provider failure is returned"(String type) {
        given:
        Authenticator authenticator = authenticator(type, [
                failing(type, AuthenticationFailureReason.USER_NOT_FOUND, SLOW_MILLIS),
                throwing(type, new RuntimeException('boom')),
        ])

        when:
        AuthenticationResponse rsp = Mono.from(authenticator.authenticate(null, credentials())).block()

        then:
        noExceptionThrown()
        rsp instanceof AuthenticationFailed
        ((AuthenticationFailed) rsp).reason == AuthenticationFailureReason.USER_NOT_FOUND

        where:
        type << [IMPERATIVE, IMPERATIVE_BLOCKING, REACTIVE]
    }

    @Unroll
    void "#type providers: when the first provider throws, an AuthenticationFailed is returned instead of an error"(String type) {
        given:
        Authenticator authenticator = authenticator(type, [
                throwing(type, new RuntimeException('boom'), SLOW_MILLIS),
                failing(type, AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
        ])

        when:
        AuthenticationResponse rsp = Mono.from(authenticator.authenticate(null, credentials())).block()

        then:
        noExceptionThrown()
        rsp instanceof AuthenticationFailed
        ((AuthenticationFailed) rsp).reason == AuthenticationFailureReason.CUSTOM
        rsp.message.get() == 'boom'

        where:
        type << [IMPERATIVE, IMPERATIVE_BLOCKING, REACTIVE]
    }

    @Unroll
    void "#type providers: a later successful provider still wins"(String type) {
        given:
        Authenticator authenticator = authenticator(type, [
                failing(type, AuthenticationFailureReason.USER_NOT_FOUND),
                throwing(type, new RuntimeException('boom')),
                succeeding(type, 'sherlock'),
        ])

        when:
        AuthenticationResponse rsp = Mono.from(authenticator.authenticate(null, credentials())).block()

        then:
        rsp.authenticated
        rsp.authentication.get().name == 'sherlock'

        where:
        type << [IMPERATIVE, IMPERATIVE_BLOCKING, REACTIVE]
    }

    private static UsernamePasswordCredentials credentials() {
        new UsernamePasswordCredentials('sherlock', 'password')
    }

    private Authenticator authenticator(String type, List providers) {
        type == REACTIVE
                ? new Authenticator(ctx, providers, [], new SecurityConfigurationProperties())
                : new Authenticator(ctx, [], providers, new SecurityConfigurationProperties())
    }

    private failing(String type, AuthenticationFailureReason reason, long delayMillis = 0) {
        provider(type, { AuthenticationResponse.failure(reason) }, delayMillis)
    }

    private throwing(String type, RuntimeException e, long delayMillis = 0) {
        provider(type, { throw e }, delayMillis)
    }

    private succeeding(String type, String username) {
        provider(type, { AuthenticationResponse.success(username) }, 0)
    }

    private provider(String type, Closure<AuthenticationResponse> response, long delayMillis) {
        switch (type) {
            case IMPERATIVE:
                return Stub(AuthenticationProvider) {
                    authenticate(_, _) >> { Thread.sleep(delayMillis); response() }
                }
            case IMPERATIVE_BLOCKING:
                // forces the imperative provider through the reactive path via AuthenticationProviderAdapter
                return Stub(ExecutorAuthenticationProvider) {
                    getExecutorName() >> TaskExecutors.BLOCKING
                    authenticate(_, _) >> { Thread.sleep(delayMillis); response() }
                }
            case REACTIVE:
                return Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> { Flux.defer({ Flux.just(response()) }).delaySubscription(Duration.ofMillis(delayMillis)) }
                }
            default:
                throw new IllegalArgumentException(type)
        }
    }
}
