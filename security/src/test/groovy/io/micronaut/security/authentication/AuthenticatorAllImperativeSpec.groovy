package io.micronaut.security.authentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "micronaut.security.authentication-provider-strategy", value = "ALL")
@Property(name = "spec.name", value = "AuthenticatorAllImperativeSpec")
@MicronautTest
class AuthenticatorAllImperativeSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "imperative auth provider"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        String expected = '{"message":"Hello World"}'

        when:
        String json = client.retrieve(createRequest("watson", "password"))

        then:
        noExceptionThrown()
        expected == json

        when:
        client.retrieve(createRequest("sherlock", "password"))

        then:
        HttpClientResponseException ex = thrown()
        HttpStatus.UNAUTHORIZED == ex.status

        when:
        client.retrieve(createRequest("moriarty", "password"))

        then:
        ex = thrown()
        HttpStatus.UNAUTHORIZED == ex.status

        when:
        client.retrieve(createRequest("user", "wrong"))

        then:
        ex = thrown()
        HttpStatus.UNAUTHORIZED == ex.status
    }

    private HttpRequest<?> createRequest(String userName, String password) {
        return HttpRequest.GET("/messages").basicAuth(userName, password)
    }

    @Requires(property = "spec.name", value = "AuthenticatorAllImperativeSpec")
    @Controller("/messages")
    static class HelloWorldController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, Object> index() {
            [message: "Hello World"]
        }
    }

    @Requires(property = "spec.name", value = "AuthenticatorAllImperativeSpec")
    @Singleton
    static class SherlockAuthenticationProvider implements io.micronaut.security.authentication.provider.AuthenticationProvider {
        @Override
        AuthenticationResponse authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest authRequest) {
            if (authRequest.identity == "sherlock" || authRequest.identity == 'watson') {
                return AuthenticationResponse.success(authRequest.identity.toString())
            }
            AuthenticationResponse.failure()
        }
    }

    @Requires(property = "spec.name", value = "AuthenticatorAllImperativeSpec")
    @Singleton
    static class MoriartyAuthenticationProvider implements io.micronaut.security.authentication.provider.AuthenticationProvider {
        @Override
        AuthenticationResponse authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest authRequest) {
            if (authRequest.identity == "moriarty" || authRequest.identity == 'watson') {
                return AuthenticationResponse.success(authRequest.identity.toString())
            }
            AuthenticationResponse.failure()
        }
    }
}
