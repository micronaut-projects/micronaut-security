package io.micronaut.security.docs.authentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.ClientAuthentication
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.security.context.SecurityContextHolder
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "RunAsTest")
@MicronautTest
internal class RunAsTest {

    @Test
    fun verifyYouCanUseTheRunAsAnnotationToChangeTheSecurityContextHolderForTheScopeOfAClass(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()
        val authentications = client.retrieve(
            HttpRequest.GET<Any>("/runAs").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication::class.java)
        )
        val runAsExpected = Authentication.build(
            "aegon",
            listOf("ROLE_KING"),
            mapOf("family_name" to "Targaryen", "roles" to listOf("ROLE_KING"))
        )
        var authentication: Authentication = authentications[0]
        Assertions.assertEquals(runAsExpected.name, authentication.name)
        Assertions.assertEquals(runAsExpected.roles.toList(), authentication.roles.toList())
        Assertions.assertEquals(runAsExpected.attributes, authentication.attributes)

        val expected = Authentication.build(
            "john",
            listOf("ROLE_STARK"),
            mapOf("family_name" to "Snow", "given_name" to "John", "roles" to listOf("ROLE_STARK"))
        )
        authentication = authentications[1]
        Assertions.assertEquals(expected.name, authentication.name)
        Assertions.assertEquals(expected.roles.toList(), authentication.roles.toList())
        Assertions.assertEquals(expected.attributes, authentication.attributes)
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    internal class RunAsAuthenticationProvider : HttpRequestAuthenticationProvider<Any> {
        override fun authenticate(
            requestContext: HttpRequest<Any>?,
            authRequest: AuthenticationRequest<String, String>
        ): AuthenticationResponse {
            return AuthenticationResponse.success(
                "john",
                listOf("ROLE_STARK"),
                mapOf("family_name" to "Snow", "given_name" to "John")
            )
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Controller("/runAs")
    internal class RunAsController(
        private val runAuthService: RunAsAuthService,
        private val authService: AuthService
    ) {

        @Secured("ROLE_STARK")
        @Get
        fun index(authentication: Authentication): List<Authentication> {
            return listOf(runAuthService.changeAuth()!!, authService.auth()!!)
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    internal class AuthService {
        fun auth(): Authentication? {
            return SecurityContextHolder.getSecurityContext().authentication
        }
    }
}
