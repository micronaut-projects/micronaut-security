package io.micronaut.security.oauth2.docs.endpoint;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "OAuthCsrfFilterTest")
@Property(name = "oauth.csrf", value = "true")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.oauth2.clients.twitter.authorization.url", value = "https://twitter.com/authorize")
@Property(name = "micronaut.security.oauth2.clients.twitter.token.url", value = "https://twitter.com/token")
@Property(name = "micronaut.security.oauth2.clients.twitter.client-id", value = "myclient")
@Property(name = "micronaut.security.oauth2.clients.twitter.client-secret", value = "mysecret")
@MicronautTest
class OAuthCsrfFilterTest {

    @Test
    void rejectsALoginWithoutTheToken(@Client("/") HttpClient client) {
        assertForbidden(client, HttpRequest.GET("/oauth/login/twitter"));
        assertForbidden(client, HttpRequest.GET("/oauth/login/twitter").cookie(Cookie.of("_csrf", "token-fixture")));
        assertForbidden(client, HttpRequest.GET("/oauth/login/twitter?_csrf=token-fixture"));
    }

    @Test
    void rejectsALoginWithADifferentToken(@Client("/") HttpClient client) {
        assertForbidden(client, HttpRequest.GET("/oauth/login/twitter?_csrf=other-token-fixture")
            .cookie(Cookie.of("_csrf", "token-fixture")));
    }

    @Test
    void allowsALoginWithTheToken(@Client("/") HttpClient client) {
        HttpResponse<?> response = client.toBlocking().exchange(HttpRequest.GET("/oauth/login/twitter?_csrf=token-fixture")
            .cookie(Cookie.of("_csrf", "token-fixture")));

        assertEquals(HttpStatus.FOUND, response.getStatus());
    }

    private static void assertForbidden(HttpClient client, HttpRequest<?> request) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.toBlocking().exchange(request));
        assertEquals(HttpStatus.FORBIDDEN, e.getStatus());
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OAuthCsrfFilterTest")
    static class TwitterAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("twitterUser"));
        }
    }
}
