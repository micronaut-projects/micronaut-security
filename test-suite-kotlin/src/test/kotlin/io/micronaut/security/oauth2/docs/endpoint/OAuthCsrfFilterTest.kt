package io.micronaut.security.oauth2.docs.endpoint

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

@Property(name = "spec.name", value = "OAuthCsrfFilterTest")
@Property(name = "oauth.csrf", value = "true")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.oauth2.clients.twitter.authorization.url", value = "https://twitter.com/authorize")
@Property(name = "micronaut.security.oauth2.clients.twitter.token.url", value = "https://twitter.com/token")
@Property(name = "micronaut.security.oauth2.clients.twitter.client-id", value = "myclient")
@Property(name = "micronaut.security.oauth2.clients.twitter.client-secret", value = "mysecret")
@MicronautTest
internal class OAuthCsrfFilterTest {

    @Test
    fun rejectsALoginWithoutTheToken(@Client("/") client: HttpClient) {
        assertForbidden(client, HttpRequest.GET<Any>("/oauth/login/twitter"))
        assertForbidden(client, HttpRequest.GET<Any>("/oauth/login/twitter").cookie(Cookie.of("_csrf", "token-fixture")))
        assertForbidden(client, HttpRequest.GET<Any>("/oauth/login/twitter?_csrf=token-fixture"))
    }

    @Test
    fun rejectsALoginWithADifferentToken(@Client("/") client: HttpClient) {
        assertForbidden(client, HttpRequest.GET<Any>("/oauth/login/twitter?_csrf=other-token-fixture")
            .cookie(Cookie.of("_csrf", "token-fixture")))
    }

    @Test
    fun allowsALoginWithTheToken(@Client("/") client: HttpClient) {
        val response = client.toBlocking().exchange<Any, Any>(HttpRequest.GET<Any>("/oauth/login/twitter?_csrf=token-fixture")
            .cookie(Cookie.of("_csrf", "token-fixture")))

        assertEquals(HttpStatus.FOUND, response.status)
    }

    private fun assertForbidden(client: HttpClient, request: HttpRequest<Any>) {
        val e = assertThrows(HttpClientResponseException::class.java) {
            client.toBlocking().exchange<Any, Any>(request)
        }
        assertEquals(HttpStatus.FORBIDDEN, e.status)
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OAuthCsrfFilterTest")
    internal class TwitterAuthenticationMapper : OauthAuthenticationMapper {
        override fun createAuthenticationResponse(tokenResponse: TokenResponse, state: State?): Publisher<AuthenticationResponse> =
            Mono.just(AuthenticationResponse.success("twitterUser"))
    }
}
