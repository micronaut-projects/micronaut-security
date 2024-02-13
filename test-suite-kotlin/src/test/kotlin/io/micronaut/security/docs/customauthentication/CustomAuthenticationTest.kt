package io.micronaut.security.docs.customauthentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

@Property(name = "spec.name", value = "CustomAuthenticationTest")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@MicronautTest
internal class CustomAuthenticationTest {
    @Test
    fun customAuthentication(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val request: HttpRequest<*> = HttpRequest.GET<Any>("/custom-authentication")
            .accept(MediaType.TEXT_PLAIN)
            .bearerAuth("xxx")
        val email = Assertions.assertDoesNotThrow<String> {
            client.retrieve(request)
        }
        Assertions.assertEquals("sherlock@micronaut.example", email)
    }

    @Requires(property = "spec.name", value = "CustomAuthenticationTest")
    @Controller
    internal class CustomAuthenticationController {
//tag::method[]
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/custom-authentication")
        fun index(authentication: AuthenticationWithEmail) = authentication.email
//end::method[]
    }

    @Requires(property = "spec.name", value = "CustomAuthenticationTest")
    @Controller
    internal class CustomAuthenticationProvider : TokenValidator<HttpRequest<*>> {
        override fun validateToken(token: String, request: HttpRequest<*>): Publisher<Authentication> {
            return Mono.just(Authentication.build("sherlock", mapOf("email" to "sherlock@micronaut.example")))
        }
    }
}
