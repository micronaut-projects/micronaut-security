package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
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
import spock.lang.Specification

@Property(name = "spec.name", value = "AuthenticationProviderTest")
@MicronautTest
class AuthenticationProviderTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "blockingAuthProvider"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        String expected = '{"message":"Hello World"}'

        when:
        String json = client.retrieve(createRequest("user", "password"))

        then:
        noExceptionThrown()
        expected == json

        when:
        client.retrieve(createRequest("user", "wrong"))

        then:
        HttpClientResponseException ex = thrown()
        HttpStatus.UNAUTHORIZED == ex.status
    }

    private HttpRequest<?> createRequest(String userName, String password) {
        return HttpRequest.GET("/messages").basicAuth(userName, password)
    }

    @Requires(property = "spec.name", value = "AuthenticationProviderTest")
    @Controller("/messages")
    static class HelloWorldController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, Object> index() {
            [message: "Hello World"]
        }
    }
}
