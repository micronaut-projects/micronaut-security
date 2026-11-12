package io.micronaut.security.authentication

import io.micronaut.context.ApplicationContext
import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider
import io.micronaut.security.config.SecurityConfigurationProperties
import jakarta.inject.Singleton
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * {@link Authenticator} builds its provider chain (reactive providers plus imperative providers adapted to reactive,
 * sorted by order, each {@link ExecutorAuthenticationProvider} bound to its executor) once, at construction time,
 * rather than on every authentication. A provider naming an executor that does not exist as a bean is a
 * configuration error reported when the Authenticator is created, not silently run inline on the caller thread.
 */
class AuthenticatorProviderChainSpec extends Specification {

    static final String MISSING_EXECUTOR = 'does-not-exist'

    void "an ExecutorAuthenticationProvider naming an executor that does not exist fails Authenticator construction with a ConfigurationException"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()
        ExecutorAuthenticationProvider provider = Stub(ExecutorAuthenticationProvider) {
            getExecutorName() >> MISSING_EXECUTOR
            authenticate(_, _) >> { AuthenticationResponse.success('sherlock') }
        }

        when:
        new Authenticator(ctx, [], [provider], new SecurityConfigurationProperties())

        then:
        ConfigurationException e = thrown()
        e.message.contains(MISSING_EXECUTOR)
        e.message.contains(provider.getClass().getName())
        e.message.contains(ExecutorService.class.getName())

        cleanup:
        ctx.close()
    }

    void "an ExecutorAuthenticationProvider bean naming an executor that does not exist fails Authenticator bean creation with a ConfigurationException"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(['spec.name': 'AuthenticatorProviderChainSpec'])

        when:
        ctx.getBean(Authenticator)

        then:
        Throwable t = thrown()
        ConfigurationException e = configurationException(t)
        e != null
        e.message.contains(MISSING_EXECUTOR)
        e.message.contains(MissingExecutorAuthenticationProvider.class.getName())

        cleanup:
        ctx.close()
    }

    void "the provider chain is built once: the executor bean is resolved once across several authentications"() {
        given:
        ExecutorService executor = Executors.newSingleThreadExecutor()
        AtomicInteger executorLookups = new AtomicInteger()
        AtomicInteger executorNameCalls = new AtomicInteger()
        BeanContext beanContext = Stub(BeanContext) {
            findBean(ExecutorService, _) >> { executorLookups.incrementAndGet(); Optional.of(executor) }
        }
        List providers = (1..2).collect {
            Stub(ExecutorAuthenticationProvider) {
                getExecutorName() >> { executorNameCalls.incrementAndGet(); TaskExecutors.BLOCKING }
                authenticate(_, _) >> { AuthenticationResponse.failure() }
            }
        }
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('sherlock', 'password')

        when:
        Authenticator authenticator = new Authenticator(beanContext, [], providers, new SecurityConfigurationProperties())
        AuthenticationResponse first = Mono.from(authenticator.authenticate(null, creds)).block()
        AuthenticationResponse second = Mono.from(authenticator.authenticate(null, creds)).block()

        then: 'both providers share the executor name, so it is resolved exactly once, at construction, not per authentication'
        executorLookups.get() == 1
        first instanceof AuthenticationFailed
        second instanceof AuthenticationFailed

        and: 'the chain field is populated once and reused for every authentication'
        def field = Authenticator.getDeclaredField('everyProviderSorted')
        field.setAccessible(true)
        List chain = field.get(authenticator)
        chain.size() == providers.size()
        field.get(authenticator).is(chain)

        cleanup:
        executor.shutdownNow()
    }

    void "an ExecutorAuthenticationProvider runs on the executor bean it names"() {
        given:
        String threadName = 'authenticator-provider-chain-spec'
        ExecutorService executor = Executors.newSingleThreadExecutor { Runnable r -> new Thread(r, threadName) }
        BeanContext beanContext = Stub(BeanContext) {
            findBean(ExecutorService, _) >> Optional.of(executor)
        }
        // only the blocking and io executor names route an imperative provider through the reactive path (see
        // Authenticator#isImperativeAuthenticationProviderIsBlocking); any other name runs the provider inline
        ExecutorAuthenticationProvider provider = Stub(ExecutorAuthenticationProvider) {
            getExecutorName() >> TaskExecutors.IO
            authenticate(_, _) >> { AuthenticationResponse.success(Thread.currentThread().name) }
        }
        Authenticator authenticator = new Authenticator(beanContext, [], [provider], new SecurityConfigurationProperties())

        when:
        AuthenticationResponse rsp = Mono.from(authenticator.authenticate(null, new UsernamePasswordCredentials('sherlock', 'password'))).block()

        then:
        rsp.authenticated
        rsp.authentication.get().name == threadName

        cleanup:
        executor.shutdownNow()
    }

    private static ConfigurationException configurationException(Throwable t) {
        Throwable current = t
        while (current != null) {
            if (current instanceof ConfigurationException) {
                return (ConfigurationException) current
            }
            current = current.cause
        }
        return null
    }

    @Requires(property = 'spec.name', value = 'AuthenticatorProviderChainSpec')
    @Singleton
    static class MissingExecutorAuthenticationProvider<T> implements ExecutorAuthenticationProvider<T, String, String> {

        @Override
        String getExecutorName() {
            MISSING_EXECUTOR
        }

        @Override
        AuthenticationResponse authenticate(T requestContext, AuthenticationRequest<String, String> authenticationRequest) {
            AuthenticationResponse.success('sherlock')
        }
    }
}
