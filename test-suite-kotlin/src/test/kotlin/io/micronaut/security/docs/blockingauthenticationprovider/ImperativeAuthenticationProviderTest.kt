package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "ImperativeAuthenticationProviderTest")
@MicronautTest
internal class ImperativeAuthenticationProviderTest {
    @Test
    fun blockingAuthProvider(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val json = Assertions.assertDoesNotThrow<String> {
            client.retrieve(createRequest("user", "password"))
        }
        val expected = """{"message":"Hello World"}"""
        Assertions.assertEquals(expected, json)
        val ex = Assertions.assertThrows(HttpClientResponseException::class.java) {
            client.retrieve(createRequest("user", "wrong"))
        }
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, ex.status)
    }

    private fun createRequest(userName: String, password: String): HttpRequest<*> {
        return HttpRequest.GET<Any>("/messages").basicAuth(userName, password)
    }

    @Requires(property = "spec.name", value = "ImperativeAuthenticationProviderTest")
    @Controller("/messages")
    internal class HelloWorldController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        fun index(): Map<String, Any> = mapOf("message" to "Hello World")
    }
}
