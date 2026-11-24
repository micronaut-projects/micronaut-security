package io.micronaut.security.test.tomcat;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * On the Tomcat runtime, the route is resolved before the Fetch Metadata filter runs, so the OAuth 2.0 login route
 * is closed to cross-site navigation there too.
 */
@Property(name = "spec.name", value = "OauthLoginFetchMetadataTomcatTest")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "test-fixture-not-a-secret-test-fixture-not-a-secret")
@Property(name = "micronaut.security.oauth2.default-provider", value = "auth")
@Property(name = "micronaut.security.oauth2.clients.auth.authorization.url", value = "https://provider.example/authorize")
@Property(name = "micronaut.security.oauth2.clients.auth.token.url", value = "https://provider.example/token")
@Property(name = "micronaut.security.oauth2.clients.auth.client-id", value = "client-id-fixture")
@Property(name = "micronaut.security.oauth2.clients.auth.client-secret", value = "client-secret-fixture-not-a-secret")
@MicronautTest
class OauthLoginFetchMetadataTomcatTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    EmbeddedServer server;

    @Test
    void runsOnTomcat() {
        assertTrue(server.getClass().getName().toLowerCase().contains("tomcat"), server.getClass().getName());
    }

    @Test
    void crossSiteNavigationToTheLoginRoutesIsRejected() {
        for (String path : new String[] {"/oauth/login/auth", "/oauth/login"}) {
            HttpResponse<?> response = exchange(navigation(path, "cross-site"));

            assertEquals(HttpStatus.FORBIDDEN, response.status(), path);
            assertNull(response.getHeaders().get(HttpHeaders.LOCATION), path);
            assertTrue(response.getHeaders().getAll(HttpHeaders.SET_COOKIE).isEmpty(), path);
        }
    }

    @Test
    void sameOriginNavigationToTheLoginRouteRedirectsToTheProvider() {
        HttpResponse<?> response = exchange(navigation("/oauth/login/auth", "same-origin"));

        assertEquals(HttpStatus.FOUND, response.status());
        assertTrue(response.getHeaders().get(HttpHeaders.LOCATION).startsWith("https://provider.example/authorize?"));
        assertEquals("no-store", response.getHeaders().get(HttpHeaders.CACHE_CONTROL));
    }

    private HttpResponse<?> exchange(HttpRequest<?> request) {
        try {
            return httpClient.toBlocking().exchange(request);
        } catch (HttpClientResponseException e) {
            return e.getResponse();
        }
    }

    private static HttpRequest<?> navigation(String path, String site) {
        return HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, site)
            .header(HttpHeaders.SEC_FETCH_MODE, "navigate")
            .header(HttpHeaders.SEC_FETCH_DEST, "document");
    }

    @Requires(property = "spec.name", value = "OauthLoginFetchMetadataTomcatTest")
    @Singleton
    @Named("auth")
    static class AuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("user"));
        }
    }
}
