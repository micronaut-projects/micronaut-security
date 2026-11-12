package io.micronaut.security.docs.securityrule.permitall

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "PermitAllTest")
@MicronautTest
internal class PermitAllTest {

    @Test
    fun permitAllEndpointCanBeAccessedWithoutAuthentication(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        assertDoesNotThrow { client.exchange<Any, Any>(HttpRequest.GET("/example/anonymous")) }
    }

    @Test
    fun rolesAllowedEndpointRequiresOneOfTheRoles(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        var ex = assertThrows(HttpClientResponseException::class.java) {
            client.exchange<Any, Any>(HttpRequest.GET("/example/admin"))
        }
        assertEquals(HttpStatus.UNAUTHORIZED, ex.status)
        ex = assertThrows(HttpClientResponseException::class.java) {
            client.exchange<Any, Any>(HttpRequest.GET<Any>("/example/admin").basicAuth("user", "password"))
        }
        assertEquals(HttpStatus.FORBIDDEN, ex.status)
        assertDoesNotThrow { client.exchange<Any, Any>(HttpRequest.GET<Any>("/example/admin").basicAuth("admin", "password")) }
    }

    @Requires(property = "spec.name", value = "PermitAllTest")
    @Singleton
    internal class AuthenticationProviderUserPassword<B : Any> : HttpRequestAuthenticationProvider<B> {
        override fun authenticate(requestContext: HttpRequest<B>?, authRequest: AuthenticationRequest<String, String>): AuthenticationResponse =
            when (authRequest.identity) {
                "user" -> AuthenticationResponse.success("user")
                "admin" -> AuthenticationResponse.success("admin", listOf("ROLE_ADMIN"))
                else -> AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND)
            }
    }
}
