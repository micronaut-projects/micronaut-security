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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.UUID

@Property(name = "spec.name", value = "SiteminderAuthorizationTest")
@MicronautTest
internal class SiteminderAuthorizationTest {

    @Test
    fun customSiteMinderAuthenticationFetcher(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val username = UUID.randomUUID().toString()
        val request = HttpRequest.GET<Any>("/sm").header(SiteminderAuthenticationFetcher.SITEMINDER_USER_HEADER, username)
        assertEquals(username, client.retrieve(request))
    }

    @Requires(property = "spec.name", value = "SiteminderAuthorizationTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/sm")
    internal class MyController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        fun username(authentication: Authentication): String = authentication.name
    }
}
