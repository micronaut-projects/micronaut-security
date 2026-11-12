package io.micronaut.security.docs.bearerauth

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.render.BearerAccessRefreshToken
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "BearerAuthTest")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest
internal class BearerAuthTest {

    @Test
    fun bearerAuthSetsTheAuthorizationHeaderWithTheBearerToken(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val creds = UsernamePasswordCredentials("sherlock", "password")
        val rsp = client.exchange(HttpRequest.POST("/login", creds), BearerAccessRefreshToken::class.java)
        assertEquals(HttpStatus.OK, rsp.status())
        assertNotNull(rsp.body())

        // tag::bearerAuth[]
        val accessToken: String = rsp.body()!!.accessToken
        val books: List<Book> = client.retrieve(HttpRequest.GET<Any>("/api/gateway")
                .bearerAuth(accessToken), Argument.listOf(Book::class.java))
        // end::bearerAuth[]
        assertEquals(2, books.size)
    }

    @Requires(property = "spec.name", value = "BearerAuthTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/api")
    internal class GatewayController {
        @Get("/gateway")
        fun findAll(): List<Book> = listOf(Book("1491950358", "Building Microservices"),
                Book("1680502395", "Release It!"))
    }

    @Requires(property = "spec.name", value = "BearerAuthTest")
    @Singleton
    internal class AuthenticationProviderUserPassword<B : Any> : HttpRequestAuthenticationProvider<B> {
        override fun authenticate(requestContext: HttpRequest<B>?, authRequest: AuthenticationRequest<String, String>): AuthenticationResponse =
            if (authRequest.identity == "sherlock" && authRequest.secret == "password") AuthenticationResponse.success("sherlock")
            else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }
}
