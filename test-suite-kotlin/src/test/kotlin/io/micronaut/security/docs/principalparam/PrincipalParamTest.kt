package io.micronaut.security.docs.principalparam

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "PrincipalParamTest")
@MicronautTest
internal class PrincipalParamTest {

    @Test
    fun principalCanBeUsedAsAControllerParameterToGetTheLoggedInUser(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        var rsp = client.exchange(HttpRequest.GET<Any>("/user/myinfo"), Argument.mapOf(String::class.java, Any::class.java))
        assertEquals(HttpStatus.OK, rsp.status())
        assertFalse(rsp.body()!!.containsKey("username"))

        rsp = client.exchange(HttpRequest.GET<Any>("/user/myinfo").basicAuth("user", "password"), Argument.mapOf(String::class.java, Any::class.java))
        assertEquals(HttpStatus.OK, rsp.status())
        assertTrue(rsp.body()!!.containsKey("username"))
        assertEquals("user", rsp.body()!!["username"])
    }

    @Requires(property = "spec.name", value = "PrincipalParamTest")
    @Singleton
    internal class AuthenticationProviderUserPassword<B : Any> : HttpRequestAuthenticationProvider<B> {
        override fun authenticate(requestContext: HttpRequest<B>?, authRequest: AuthenticationRequest<String, String>): AuthenticationResponse =
            if (authRequest.identity == "user" && authRequest.secret == "password") AuthenticationResponse.success("user")
            else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }
}
