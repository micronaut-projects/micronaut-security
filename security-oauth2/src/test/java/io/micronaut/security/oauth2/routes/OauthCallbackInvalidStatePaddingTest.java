package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Java4Shell (CVE-2026-114938): a callback whose state carries a vulnerable Base64 tail is a failed login,
 * not a server error.
 */
@Property(name = "spec.name", value = "OauthCallbackInvalidStatePaddingTest")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/failed")
@Property(name = "micronaut.security.oauth2.clients.example.client-id", value = "client")
@Property(name = "micronaut.security.oauth2.clients.example.client-secret", value = "secret")
@Property(name = "micronaut.security.oauth2.clients.example.authorization.url", value = "http://localhost:1/authorize")
@Property(name = "micronaut.security.oauth2.clients.example.token.url", value = "http://localhost:1/token")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@MicronautTest
class OauthCallbackInvalidStatePaddingTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @ParameterizedTest
    @ValueSource(ints = {64, 128})
    void callbackWithJava4ShellStateIsAFailedLogin(int prefixLength) {
        BlockingHttpClient client = httpClient.toBlocking();
        String state = URLEncoder.encode("A".repeat(prefixLength) + "=", StandardCharsets.UTF_8);

        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/callback/example?code=abc&state=" + state));

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/login/failed", response.getHeaders().get(HttpHeaders.LOCATION));
    }

    @Requires(property = "spec.name", value = "OauthCallbackInvalidStatePaddingTest")
    @Named("example")
    @Singleton
    static class ExampleAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            return Mono.just(AuthenticationResponse.success("user"));
        }
    }
}
