package io.micronaut.security.authentication.provider

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

@Property(name = "spec.name", value = "HttpRequestReactiveAuthenticationProviderSpec")
@MicronautTest
class HttpRequestReactiveAuthenticationProviderSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "imperative auth provider"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        String expected = '{"message":"Hello World"}'

        when:
        String json = client.retrieve(createRequest("sherlock", "password").header("X-API-Version", "v1"))

        then:
        noExceptionThrown()
        expected == json

        when:
        client.retrieve(createRequest("sherlock", "password"))

        then:
        HttpClientResponseException ex = thrown()
        HttpStatus.UNAUTHORIZED == ex.status
    }

    private MutableHttpRequest<?> createRequest(String userName, String password) {
        HttpRequest.GET("/messages").basicAuth(userName, password)
    }

    @Requires(property = "spec.name", value = "HttpRequestReactiveAuthenticationProviderSpec")
    @Singleton
    static class SherlockAuthenticationProvider implements HttpRequestReactiveAuthenticationProvider {
        @Override
        @SingleResult
        Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest httpRequest, @NonNull AuthenticationRequest authRequest) {
            Mono.just((httpRequest.headers.contains("X-API-Version") && authRequest.identity == "sherlock")
                    ? AuthenticationResponse.success(authRequest.identity.toString())
                    : AuthenticationResponse.failure())
        }
    }

    @Requires(property = "spec.name", value = "HttpRequestReactiveAuthenticationProviderSpec")
    @Controller("/messages")
    static class HelloWorldController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, Object> index() {
            [message: "Hello World"]
        }
    }
}
