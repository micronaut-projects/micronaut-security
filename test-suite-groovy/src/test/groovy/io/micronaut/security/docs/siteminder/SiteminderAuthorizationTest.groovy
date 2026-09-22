package io.micronaut.security.docs.siteminder

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "SiteminderAuthorizationTest")
@MicronautTest
class SiteminderAuthorizationTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "custom SiteMinder authentication fetcher"() {
        given:
        String username = UUID.randomUUID()

        when:
        HttpRequest request = HttpRequest.GET('/sm').header(SiteminderAuthenticationFetcher.SITEMINDER_USER_HEADER, username)

        then:
        httpClient.toBlocking().retrieve(request) == username
    }

    @Requires(property = "spec.name", value = "SiteminderAuthorizationTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/sm")
    static class MyController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }
}
