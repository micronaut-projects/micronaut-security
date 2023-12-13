package io.micronaut.security.authentication

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Blocking
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.provider.AuthenticationProvider
import io.micronaut.security.authentication.provider.AuthenticationProviderUtils
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "AuthenticationProviderUtilsTest")
@MicronautTest(startApplication = false)
class AuthenticationProviderUtilsTest extends Specification {

    @Inject
    BeanContext beanContext

    void "#clazz authenticate method is #description"(boolean isBlocking,
                                                      Class<? extends AuthenticationProvider> clazz,
                                                      String description) {
        expect:
        isBlocking == AuthenticationProviderUtils.isAuthenticateBlocking(beanContext, beanContext.getBean(clazz))

        where:
        isBlocking | clazz
        true       | BlockingAuthenticationProvider.class
        true       | BlockingWithGenericAuthenticationProvider
        false      | NonBlockingAuthenticationProvider.class
        description = isBlocking ? "is annotated with @Blocking" : "is not annotated with @Blocking"
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderUtilsTest")
    @Singleton
    static class BlockingAuthenticationProvider implements AuthenticationProvider<HttpRequest> {
        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable HttpRequest httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderUtilsTest")
    @Singleton
    static class BlockingWithGenericAuthenticationProvider<T> implements AuthenticationProvider<T> {
        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable T httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderUtilsTest")
    @Singleton
    static class NonBlockingAuthenticationProvider implements AuthenticationProvider<HttpRequest> {
        @Override
        AuthenticationResponse authenticate(@Nullable HttpRequest httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }
    }

}
