package io.micronaut.security.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.security.testutils.ApplicationContextSpecification
import jakarta.inject.Singleton

class BasicAuthAuthenticationFetcherSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        return "BasicAuthAuthenticationFetcherSpec"
    }

    void "by default BasicAuthAuthenticationFetcher exists"() {
        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)
    }

    @Requires(property = "spec.name", value = "BasicAuthAuthenticationFetcherSpec")
    @Singleton
    static class CustomAuthenticationProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }
}
