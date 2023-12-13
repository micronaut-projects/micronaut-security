package io.micronaut.security.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Blocking
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.scheduling.LoomSupport
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.testutils.ApplicationContextSpecification
import jakarta.inject.Named
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

class ImperativeAuthenticationProviderSpec extends ApplicationContextSpecification {

    static final String EXECUTOR_NAME_MATCH = "%s-executor".formatted(LoomSupport.supported ? TaskExecutors.VIRTUAL : TaskExecutors.IO)

    SimpleImperativeAuthenticationProvider provider

    def setup() {
        provider = getBean(SimpleImperativeAuthenticationProvider.class)
        provider.executedThreadName = ""
    }

    def "multiple ImperativeAuthenticationProvider implementations are registered"() {
        given:
        BasicAuthAuthenticationFetcher authFetcher = getBean(BasicAuthAuthenticationFetcher.class)

        expect:
        authFetcher
        getApplicationContext().getBeanRegistrations(ImperativeAuthenticationProvider.class).size() == 2
    }

    def "a blocking authentication provider can authenticate successfully"() {
        given:
        BasicAuthAuthenticationFetcher authFetcher = getBean(BasicAuthAuthenticationFetcher.class)

        when:
        Authentication authentication = Mono.from(authFetcher.fetchAuthentication(HttpRequest.create(HttpMethod.POST, "/auth").basicAuth('lebowski', 'thedudeabides'))).block()

        then:
        authentication != null
        authentication.name == 'lebowski'
        provider.executedThreadName.startsWith(EXECUTOR_NAME_MATCH)
    }

    def "a blocking authentication provider can fail to authenticate"() {
        given:
        BasicAuthAuthenticationFetcher authFetcher = getBean(BasicAuthAuthenticationFetcher.class)

        when:
        Authentication authentication = Mono.from(authFetcher.fetchAuthentication(HttpRequest.create(HttpMethod.POST, "/auth").basicAuth('smoky', 'pacifist'))).block()

        then:
        authentication == null
        provider.executedThreadName.startsWith(EXECUTOR_NAME_MATCH)
    }

    @Override
    String getSpecName() {
        return "ImperativeAuthenticationProviderSpec"
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderSpec")
    @Singleton
    @Named(SimpleImperativeAuthenticationProvider.NAME)
    static class SimpleImperativeAuthenticationProvider<T> implements ImperativeAuthenticationProvider<T> {
        static final String NAME = "SimpleImperativeAuthenticationProvider"

        private String executedThreadName

        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            executedThreadName = Thread.currentThread().getName()
            if (authenticationRequest.getIdentity().toString() == 'lebowski' && authenticationRequest.getSecret().toString() == 'thedudeabides') {
                return AuthenticationResponse.success('lebowski')
            } else {
                return AuthenticationResponse.failure("Over the line.")
            }
        }

        @Override
        String getName() {
            SimpleImperativeAuthenticationProvider.NAME
        }
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderSpec")
    @Singleton
    @Named(NoOpImperativeAuthenticationProvider.NAME)
    static class NoOpImperativeAuthenticationProvider<T> implements ImperativeAuthenticationProvider<T> {
        static final String NAME = "NoOpImperativeAuthenticationProvider"

        @Override
        AuthenticationResponse authenticate(@Nullable T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            throw AuthenticationResponse.exception()
        }

        @Override
        String getName() {
            NoOpImperativeAuthenticationProvider.NAME
        }
    }
}
