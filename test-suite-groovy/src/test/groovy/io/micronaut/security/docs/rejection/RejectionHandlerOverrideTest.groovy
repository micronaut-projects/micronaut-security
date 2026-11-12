package io.micronaut.security.docs.rejection

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "RejectionHandlerOverrideTest")
@MicronautTest
class RejectionHandlerOverrideTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "the rejection handler can be overridden"() {
        when:
        httpClient.toBlocking().exchange(HttpRequest.GET("/rejection-handler"))

        then:
        HttpClientResponseException ex = thrown()
        ex.response.header("X-Reason") == "Example Header"
    }

    @Requires(property = "spec.name", value = "RejectionHandlerOverrideTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/rejection-handler")
    static class SecuredResource {

        @Get
        String foo() {
            ""
        }
    }
}
