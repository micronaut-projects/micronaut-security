package io.micronaut.security.docs.basicauth

import io.micronaut.http.HttpRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.Base64

internal class BasicAuthTest {

    @Test
    fun basicAuthSetsTheAuthorizationHeaderWithBasicBase64UsernameAndPassword() {
        // tag::basicAuth[]
        val request = HttpRequest.GET<Any>("/home").basicAuth("sherlock", "password")
        // end::basicAuth[]
        val encoded = Base64.getEncoder().encodeToString("sherlock:password".toByteArray())
        assertEquals("Basic $encoded", request.headers["Authorization"])
    }
}
