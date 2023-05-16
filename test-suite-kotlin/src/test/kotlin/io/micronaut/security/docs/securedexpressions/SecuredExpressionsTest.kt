package io.micronaut.security.docs.securedexpressions

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
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
import java.util.Map
import kotlin.collections.listOf

@Property(name = "spec.name", value = "docexpressions")
@Property(name = "micronaut.http.client.read-timeout", value = "3600s")
@MicronautTest
class SecuredExpressionsTest {
    @Inject
    @field:Client("/")
    lateinit var httpClient: HttpClient

    @Test
    fun authenticatedByEmail() {
        val client = httpClient.toBlocking()
        val response: HttpResponse<*> = client.exchange<Any, Any>(HttpRequest.GET<Any>("/authenticated/email").basicAuth("sherlock", "password"))
        Assertions.assertEquals(HttpStatus.OK, response.status())

        var e = Executable { client.exchange<Any, Any>(HttpRequest.GET<Any>("/authenticated/email").basicAuth("moriarty", "password")) }
        var thrown = Assertions.assertThrows(HttpClientResponseException::class.java, e)

        Assertions.assertEquals(HttpStatus.FORBIDDEN, thrown.status)

        e = Executable { client.exchange<Any, Any>(HttpRequest.GET<Any>("/authenticated/email").basicAuth("watson", "password")) }
        thrown = Assertions.assertThrows(HttpClientResponseException::class.java, e)
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, thrown.status)
    }

    @Requires(property = "spec.name", value = "docexpressions")
    @Singleton
    internal class AuthenticationProviderUserPassword :
        MockAuthenticationProvider<HttpRequest<Any>>(
            Arrays.asList(
                SuccessAuthenticationScenario("sherlock", listOf("ROLE_ADMIN"), Map.of<String, Any>("email", "sherlock@micronaut.example")),
                SuccessAuthenticationScenario("moriarty", listOf("ROLE_ADMIN"), Map.of<String, Any>("email", "moriarty@micronaut.example"))
            )
        )
}
