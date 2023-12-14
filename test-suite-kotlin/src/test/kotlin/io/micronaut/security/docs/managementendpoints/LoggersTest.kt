package io.micronaut.security.docs.managementendpoints

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
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
import java.util.*

@Property(name = "endpoints.health.sensitive", value = StringUtils.FALSE)
@Property(name = "endpoints.health.enabled", value = StringUtils.TRUE)
@Property(name = "endpoints.loggers.sensitive", value = StringUtils.TRUE)
@Property(name = "endpoints.loggers.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.oauth2.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "LoggersTest")
@MicronautTest
internal class LoggersTest {
    @Inject
    @field:Client("/")
    lateinit var httpClient: HttpClient

    @Test
    fun healthEndpointIsNotSecured() {
        val client = httpClient.toBlocking()
        val response: HttpResponse<*> = client.exchange<Any, Any>(HttpRequest.GET("/health"))
        Assertions.assertEquals(HttpStatus.OK, response.status())
    }

    @Test
    fun loggersEndpointIsSecured() {
        val client = httpClient.toBlocking()
        val e = Executable { client.exchange<Any, Any>(HttpRequest.GET("/loggers")) }
        val thrown = Assertions.assertThrows(HttpClientResponseException::class.java, e)
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, thrown.status)
    }

    @Test
    fun loggersEndpointIsAccessibleForUsersWithRoleROLE_SYSTEM() {
        val client = httpClient.toBlocking()
        val request: HttpRequest<*> = HttpRequest.GET<Any>("/loggers").basicAuth("system", "password")
        val response = client.exchange(request, Map::class.java)
        Assertions.assertEquals(HttpStatus.OK, response.status())
        val m = response.body()
        Assertions.assertTrue(m.containsKey("levels"))
        Assertions.assertTrue(m.containsKey("loggers"))
    }

    @Test
    fun loggersEndpointIsNotAccessibleForUsersWithoutRoleROLE_SYSTEM() {
        val client = httpClient.toBlocking()
        val e = Executable { client.exchange<Any, Any>(HttpRequest.GET<Any>("/loggers").basicAuth("user", "password")) }
        val thrown = Assertions.assertThrows(HttpClientResponseException::class.java, e)
        Assertions.assertEquals(HttpStatus.FORBIDDEN, thrown.status)
    }

    @Requires(property = "spec.name", value = "LoggersTest")
    @Singleton
    internal class AuthenticationProviderUserPassword :
        MockAuthenticationProvider<HttpRequest<Any>, Any, Any>(
            listOf(
                SuccessAuthenticationScenario("user"),
                SuccessAuthenticationScenario("system", listOf("ROLE_SYSTEM"))
            )
        )
}
