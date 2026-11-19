package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
@MicronautTest
internal class ApplicationContentSecurityPolicyGeneratorTest {

    @Test
    fun theCustomGeneratorDefinesTheResponseHeader(@Client("/") httpClient: HttpClient) {
        val response = httpClient.toBlocking().exchange(HttpRequest.GET<Any>("/csp-generator"), String::class.java)

        assertEquals("default-src 'self'; object-src 'none'", response.header("Content-Security-Policy"))
    }

    @Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator")
    internal class CspGeneratorController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        fun index(): String = "ok"
    }
}
