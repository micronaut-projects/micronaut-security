package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Distinct principals may share a raw {@code sub}: authentications validated via the UserInfo endpoint of several
 * OpenID providers are named {@code <provider>:<sub>} while the {@code sub} attribute is retained. Without a session id,
 * a signed CSRF token issued to {@code provider-b:victim} must not pass the CSRF validation of a request authenticated
 * as {@code provider-a:victim}.
 */
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.csrf.signature-key", value = "test-fixture-not-a-secret-csrf-signature-key")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "CsrfTokenBoundToProviderQualifiedUserTest")
@MicronautTest
class CsrfTokenBoundToProviderQualifiedUserTest {
    private static final String CSRF_COOKIE_NAME = "__Host-csrfToken";
    private static final String TOKEN_PROVIDER_A = "opaque-token-provider-a";
    private static final String TOKEN_PROVIDER_B = "opaque-token-provider-b";
    private static final Authentication PROVIDER_A_VICTIM = Authentication.build("provider-a:victim", Map.of("sub", "victim", "oauth2Provider", "provider-a"));
    private static final Authentication PROVIDER_B_VICTIM = Authentication.build("provider-b:victim", Map.of("sub", "victim", "oauth2Provider", "provider-b"));

    @Test
    void csrfTokenIssuedToAPrincipalOfOneProviderIsRejectedForThePrincipalOfAnotherProviderWithTheSameSubject(@Client("/") HttpClient httpClient,
                                                                                                                 CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", null);
        String tokenForProviderA = csrfTokenGenerator.generateCsrfToken(request, PROVIDER_A_VICTIM);
        String tokenForProviderB = csrfTokenGenerator.generateCsrfToken(request, PROVIDER_B_VICTIM);
        assertNotEquals(tokenForProviderA, tokenForProviderB);

        // accepted: each principal submits the CSRF token issued to it
        assertEquals("provider-a:victim", assertOk(client, TOKEN_PROVIDER_A, tokenForProviderA));
        assertEquals("provider-b:victim", assertOk(client, TOKEN_PROVIDER_B, tokenForProviderB));

        // rejected: the token issued to provider-b:victim planted in the cookie of provider-a:victim, and vice versa
        assertDenied(client, TOKEN_PROVIDER_A, tokenForProviderB);
        assertDenied(client, TOKEN_PROVIDER_B, tokenForProviderA);

        // rejected: a token bound only to the raw subject shared by both principals
        String tokenForRawSubject = csrfTokenGenerator.generateCsrfToken(request, Authentication.build("victim"));
        assertDenied(client, TOKEN_PROVIDER_A, tokenForRawSubject);
        assertDenied(client, TOKEN_PROVIDER_B, tokenForRawSubject);
    }

    private static void assertDenied(BlockingHttpClient client, String bearerToken, String csrfToken) {
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(passwordChange(bearerToken, csrfToken)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
    }

    private static String assertOk(BlockingHttpClient client, String bearerToken, String csrfToken) {
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(passwordChange(bearerToken, csrfToken), String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private static HttpRequest<?> passwordChange(String bearerToken, String csrfToken) {
        return HttpRequest.POST("/password/change", new PasswordChangeForm("victim", "evil", csrfToken))
                .bearerAuth(bearerToken)
                .cookie(Cookie.of(CSRF_COOKIE_NAME, csrfToken))
                .accept(MediaType.TEXT_HTML)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    /**
     * Mimics {@code UserInfoClientTokenValidator}: the username is qualified with the provider name, the raw {@code sub} is kept as an attribute.
     */
    @Requires(property = "spec.name", value = "CsrfTokenBoundToProviderQualifiedUserTest")
    @Singleton
    static class ProviderQualifiedTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        @NonNull
        public Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            return switch (token) {
                case TOKEN_PROVIDER_A -> Publishers.just(PROVIDER_A_VICTIM);
                case TOKEN_PROVIDER_B -> Publishers.just(PROVIDER_B_VICTIM);
                default -> Publishers.empty();
            };
        }
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToProviderQualifiedUserTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChangeForm passwordChangeForm, Authentication authentication) {
            return authentication.getName();
        }
    }

    @Serdeable
    record PasswordChangeForm(
            String username,
            String password,
            String csrfToken) {
    }
}
