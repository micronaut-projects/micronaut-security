package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
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
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.cookie.TokenCookieConfigurationProperties;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With a custom {@code micronaut.security.token.name-key}, the CSRF token issued at login must resolve the same identity
 * as the authentication rebuilt from the issued JWT on later requests, including the fallback of token based authentication
 * to the {@code sub} claim when the issued token does not carry the configured claim, and even if the authentication issued
 * at login retains a {@code sub} attribute different from its name.
 */
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.name-key", value = "email")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "test-fixture-not-a-secret-jwt-signature-key")
@Property(name = "micronaut.security.csrf.signature-key", value = "test-fixture-not-a-secret-csrf-signature-key")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "spec.name", value = "CsrfTokenBoundToUserWithCustomNameKeyTest")
@MicronautTest
class CsrfTokenBoundToUserWithCustomNameKeyTest {
    private static final String CSRF_COOKIE_NAME = "__Host-csrfToken";

    @Test
    void csrfTokenIssuedAtLoginIsValidWhenTheConfiguredNameClaimIsMissingAndRejectedForAnotherUser(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        // authentication named mapped-name with a sub attribute and no email attribute: the user is named after the sub claim on later requests
        LoginCookies mappedName = login(client, "mapped-name");
        assertEquals("mapped-name", assertOk(client, mappedName.jwt(), mappedName.csrfToken()));

        // authentication with an email attribute: the user is named after the email claim on later requests
        LoginCookies withEmail = login(client, "sherlock");
        assertEquals("sherlock@example.com", assertOk(client, withEmail.jwt(), withEmail.csrfToken()));

        // rejected: a correctly signed token issued to another user
        assertDenied(client, mappedName.jwt(), withEmail.csrfToken());
        assertDenied(client, withEmail.jwt(), mappedName.csrfToken());
    }

    private static LoginCookies login(BlockingHttpClient client, String username) {
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", username, "password", "password"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpResponse<?> loginRsp = assertDoesNotThrow(() -> client.exchange(loginRequest));
        assertEquals(HttpStatus.OK, loginRsp.getStatus());
        Optional<Cookie> jwt = loginRsp.getCookie(TokenCookieConfigurationProperties.DEFAULT_COOKIENAME);
        assertTrue(jwt.isPresent());
        Optional<Cookie> csrf = loginRsp.getCookie(CSRF_COOKIE_NAME);
        assertTrue(csrf.isPresent());
        return new LoginCookies(jwt.get().getValue(), csrf.get().getValue());
    }

    private static void assertDenied(BlockingHttpClient client, String jwt, String csrfToken) {
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(passwordChange(jwt, csrfToken)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
    }

    private static String assertOk(BlockingHttpClient client, String jwt, String csrfToken) {
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(passwordChange(jwt, csrfToken), String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private static HttpRequest<?> passwordChange(String jwt, String csrfToken) {
        return HttpRequest.POST("/password/change", new PasswordChangeForm("sherlock", "evil", csrfToken))
                .cookie(Cookie.of(TokenCookieConfigurationProperties.DEFAULT_COOKIENAME, jwt))
                .cookie(Cookie.of(CSRF_COOKIE_NAME, csrfToken))
                .accept(MediaType.TEXT_HTML)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    record LoginCookies(String jwt, String csrfToken) {
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserWithCustomNameKeyTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(
                    new SuccessAuthenticationScenario("mapped-name", Collections.emptyList(), Map.of("sub", "subject-id")),
                    new SuccessAuthenticationScenario("sherlock", Collections.emptyList(), Map.of("sub", "subject-id", "email", "sherlock@example.com"))));
        }
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserWithCustomNameKeyTest")
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
