package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.csp.ContentSecurityPolicy
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
@Property(name = "micronaut.security.csp.script-src.self", value = "true")
@MicronautTest
internal class ImagesContentSecurityPolicyGeneratorTest {

    @Test
    fun theOverriddenDirectiveReplacesTheConfiguredOne(@Client("/") httpClient: HttpClient) {
        val response = httpClient.toBlocking().exchange(HttpRequest.GET<Any>("/csp-generator-images"), String::class.java)

        val policy = ContentSecurityPolicy.of(response)
        assertNotNull(policy)
        assertEquals("img-src 'self' https://images.example.com", policy!!.imgSrc()!!.toHeaderValue())
        assertEquals("script-src 'self'", policy.scriptSrc()!!.toHeaderValue())
    }

    @Requires(property = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator-images")
    internal class ImagesController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        fun index(): String = "ok"
    }
}
