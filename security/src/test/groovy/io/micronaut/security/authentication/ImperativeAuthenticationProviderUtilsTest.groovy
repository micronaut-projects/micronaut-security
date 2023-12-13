package io.micronaut.security.authentication

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Blocking
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "ImperativeAuthenticationProviderUtilsTest")
@MicronautTest(startApplication = false)
class ImperativeAuthenticationProviderUtilsTest extends Specification {

    @Inject
    BeanContext beanContext

    void "#clazz authenticate method is #description"(boolean isBlocking,
                                                      Class<? extends ImperativeAuthenticationProvider> clazz,
                                                      String description) {
        expect:
        isBlocking == ImperativeAuthenticationProviderUtils.isAuthenticateBlocking(beanContext, beanContext.getBean(clazz))

        where:
        isBlocking | clazz
        true       | BlockingImperativeAuthenticationProvider.class
        true       | BlockingWithGenericImperativeAuthenticationProvider
        false      | NonBlockingImperativeAuthenticationProvider.class
        description = isBlocking ? "is annotated with @Blocking" : "is not annotated with @Blocking"
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderUtilsTest")
    @Singleton
    @Named("foo")
    static class BlockingImperativeAuthenticationProvider implements ImperativeAuthenticationProvider<HttpRequest> {
        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable HttpRequest httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }

        @Override
        String getName() {
            "foo"
        }
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderUtilsTest")
    @Singleton
    @Named("foo")
    static class BlockingWithGenericImperativeAuthenticationProvider<T> implements ImperativeAuthenticationProvider<T> {
        @Override
        @Blocking
        AuthenticationResponse authenticate(@Nullable T httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }

        @Override
        String getName() {
            "foo"
        }
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderUtilsTest")
    @Singleton
    @Named("bar")
    static class NonBlockingImperativeAuthenticationProvider implements ImperativeAuthenticationProvider<HttpRequest> {
        @Override
        AuthenticationResponse authenticate(@Nullable HttpRequest httpRequest, @NonNull AuthenticationRequest<?, ?> authRequest) {
            return AuthenticationResponse.failure()
        }

        @Override
        String getName() {
            "bar"
        }
    }

}
