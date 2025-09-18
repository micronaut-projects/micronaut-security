package io.micronaut.security.token.basicauth

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import jakarta.inject.Singleton
import spock.lang.Specification

class BasicAuthTokenValidatorSpec extends Specification {
    private static final Map<String, String> CONFIGURATION = Map.of("spec.name", "BasicAuthTokenValidatorSpec");
    def "BasicAuthTokenValidator is loaded because by default security is turn on"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(CONFIGURATION)
        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator not loaded if micronaut.security.enabled=false"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.enabled': false] + CONFIGURATION)

        expect:
        !applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator is loaded by default"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(CONFIGURATION)

        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator is loaded if micronaut.security.basic-auth.enabled=false"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.basic-auth.enabled': false
        ] + CONFIGURATION)

        expect:
        !applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    @Requires(property = "spec.name", value = "BasicAuthTokenValidatorSpec")
    @Singleton
    static class CustomAuthenticationProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }
}
