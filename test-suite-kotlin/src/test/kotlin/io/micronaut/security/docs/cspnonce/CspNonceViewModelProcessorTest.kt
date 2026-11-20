package io.micronaut.security.docs.cspnonce

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
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import io.micronaut.views.ModelAndView
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "CspNonceViewModelProcessorTest")
@Property(name = "micronaut.security.csp.script-src.nonce", value = "true")
@MicronautTest
internal class CspNonceViewModelProcessorTest {

    @Test
    fun theViewRendersTheNonceOfTheResponseHeader(@Client("/") httpClient: HttpClient) {
        val response = httpClient.toBlocking().exchange(HttpRequest.GET<Any>("/csp-nonce"), String::class.java)

        val match = Regex("<script nonce=\"([^\"]+)\">").find(response.body()!!)
        assertNotNull(match, "the view must render the nonce")
        val contentSecurityPolicy = response.header("Content-Security-Policy")
        assertNotNull(contentSecurityPolicy)
        assertTrue(contentSecurityPolicy!!.contains("'nonce-" + match!!.groupValues[1] + "'"))
    }

    @Requires(property = "spec.name", value = "CspNonceViewModelProcessorTest")
    @Controller("/csp-nonce")
    internal class CspNonceController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get
        fun index(): ModelAndView<Map<String, Any>> = ModelAndView("csp-nonce", mapOf("title" to "CSP nonce"))
    }
}
