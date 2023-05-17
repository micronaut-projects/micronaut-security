package io.micronaut.security.docs.sensitiveendpointrule

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

@Property(name = "micronaut.security.oauth2.enabled", value = StringUtils.FALSE)
@Property(name = "endpoints.beans.enabled", value = StringUtils.TRUE)
@Property(name = "endpoints.beans.sensitive", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "SensitiveEndpointRuleReplacementTest")
@MicronautTest
class SensitiveEndpointRuleReplacementTest {
    @Inject
    @field:Client("/")
    lateinit var httpClient: HttpClient
    @Test
    fun testAccessingASensitiveEndpointWithAuthenticationAndASensitiveEndpointRuleReplacementWorks() {
        val client = httpClient.toBlocking()
        var e = Executable { client.exchange<Any, Any>(HttpRequest.GET("/beans")) }
        val thrown = Assertions.assertThrows(HttpClientResponseException::class.java, e)
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, thrown.status)
        e = Executable { client.exchange<Any, Any>(HttpRequest.GET<Any>("/beans").basicAuth("user", "password")) }
        Assertions.assertDoesNotThrow(e)
    }

    @Singleton
    @Requires(property = "spec.name", value = "SensitiveEndpointRuleReplacementTest")
    internal class AuthenticationProviderUserPassword :
        MockAuthenticationProvider<HttpRequest<Any>>(listOf(SuccessAuthenticationScenario("user")))
}
