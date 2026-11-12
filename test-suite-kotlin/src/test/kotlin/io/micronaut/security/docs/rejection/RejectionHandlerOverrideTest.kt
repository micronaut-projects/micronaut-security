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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "RejectionHandlerOverrideTest")
@MicronautTest
internal class RejectionHandlerOverrideTest {

    @Test
    fun theRejectionHandlerCanBeOverridden(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val ex = assertThrows(HttpClientResponseException::class.java) {
            client.exchange<Any, Any>(HttpRequest.GET("/rejection-handler"))
        }
        assertEquals("Example Header", ex.response.header("X-Reason"))
    }

    @Requires(property = "spec.name", value = "RejectionHandlerOverrideTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/rejection-handler")
    internal class SecuredResource {
        @Get
        fun foo(): String = ""
    }
}
