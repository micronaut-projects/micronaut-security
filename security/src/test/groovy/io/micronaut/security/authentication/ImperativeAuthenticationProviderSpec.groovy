package io.micronaut.security.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Blocking
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.scheduling.LoomSupport
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.authentication.provider.AuthenticationProvider
import io.micronaut.security.testutils.ApplicationContextSpecification
import jakarta.inject.Named
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

class AuthenticationProviderSpec extends ApplicationContextSpecification {

    static final String EXECUTOR_NAME_MATCH = "%s-executor".formatted(LoomSupport.supported ? TaskExecutors.VIRTUAL : TaskExecutors.IO)

    SimpleAuthenticationProvider provider

    def setup() {
        provider = getBean(SimpleAuthenticationProvider.class)
        provider.executedThreadName = ""
    }

    def "multiple AuthenticationProvider implementations are registered"() {
        given:
        BasicAuthAuthenticationFetcher authFetcher = getBean(BasicAuthAuthenticationFetcher.class)

        expect:
        authFetcher
        getApplicationContext().getBeanRegistrations(AuthenticationProvider.class).size() == 2
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
        return "AuthenticationProviderSpec"
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderSpec")
    @Singleton
    static class SimpleAuthenticationProvider<T> implements AuthenticationProvider<T> {
        private String executedThreadName

        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable T requestContext, AuthenticationRequest<?, ?> authenticationRequest) {
            executedThreadName = Thread.currentThread().getName()
            if (authenticationRequest.getIdentity().toString() == 'lebowski' && authenticationRequest.getSecret().toString() == 'thedudeabides') {
                return AuthenticationResponse.success('lebowski')
            } else {
                return AuthenticationResponse.failure("Over the line.")
            }
        }
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderSpec")
    @Singleton
    static class NoOpAuthenticationProvider<T> implements AuthenticationProvider<T> {
        @Override
        AuthenticationResponse authenticate(@Nullable T requestContext, AuthenticationRequest<?, ?> authenticationRequest) {
            throw AuthenticationResponse.exception()
        }
    }
}
