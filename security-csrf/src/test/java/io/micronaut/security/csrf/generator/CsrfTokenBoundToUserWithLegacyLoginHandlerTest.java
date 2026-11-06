package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
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
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.LoginCookieProvider;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import io.micronaut.security.token.cookie.TokenCookieConfigurationProperties;
import io.micronaut.security.token.cookie.TokenCookieLoginHandler;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import io.micronaut.security.token.render.AccessRefreshToken;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
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
 * A subclass written before 5.5.2, using the pre-existing constructor and overriding the deprecated
 * {@code getCookies(AccessRefreshToken, HttpRequest)}, keeps its customizations on login, while the CSRF cookie it returns
 * is rebound to the authenticated user as named by the application's {@code micronaut.security.token.name-key}.
 */
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.name-key", value = "email")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "test-fixture-not-a-secret-jwt-signature-key")
@Property(name = "micronaut.security.csrf.signature-key", value = "test-fixture-not-a-secret-csrf-signature-key")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "spec.name", value = "CsrfTokenBoundToUserWithLegacyLoginHandlerTest")
@MicronautTest
class CsrfTokenBoundToUserWithLegacyLoginHandlerTest {
    private static final String CSRF_COOKIE_NAME = "__Host-csrfToken";

    @Test
    void legacyOverrideIsInvokedAndItsCsrfCookieIsReboundToTheUser(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        LoginCookies victim = login(client, "sherlock");
        LoginCookies attacker = login(client, "moriarty");

        // the legacy override customizations are kept: the CSRF cookie path and the legacy marker cookie
        assertEquals("/legacy", victim.csrfPath());
        assertTrue(victim.legacyMarker());

        // the CSRF cookie issued by the legacy override is bound to the user as named on later requests by the configured name-key
        assertEquals("sherlock@example.com", assertOk(client, victim.jwt(), victim.csrfToken()));
        assertEquals("moriarty", assertOk(client, attacker.jwt(), attacker.csrfToken()));
        assertDenied(client, victim.jwt(), attacker.csrfToken());
        assertDenied(client, attacker.jwt(), victim.csrfToken());
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
        return new LoginCookies(jwt.get().getValue(), csrf.get().getValue(), csrf.get().getPath(), loginRsp.getCookie("legacy").isPresent());
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

    record LoginCookies(String jwt, String csrfToken, String csrfPath, boolean legacyMarker) {
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserWithLegacyLoginHandlerTest")
    @Replaces(TokenCookieLoginHandler.class)
    @Singleton
    static class LegacyTokenCookieLoginHandler extends TokenCookieLoginHandler {
        LegacyTokenCookieLoginHandler(RedirectService redirectService,
                                      RedirectConfiguration redirectConfiguration,
                                      AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                      RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                      AccessTokenConfiguration accessTokenConfiguration,
                                      AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                      @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                                      List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders) {
            super(redirectService, redirectConfiguration, accessTokenCookieConfiguration, refreshTokenCookieConfiguration, accessTokenConfiguration, accessRefreshTokenGenerator, priorToLoginPersistence, loginCookieProviders);
        }

        @Override
        @SuppressWarnings("removal")
        protected List<Cookie> getCookies(AccessRefreshToken accessRefreshToken, HttpRequest<?> request) {
            List<Cookie> cookies = super.getCookies(accessRefreshToken, request);
            cookies.stream().filter(c -> c.getName().equals(CSRF_COOKIE_NAME)).forEach(c -> c.path("/legacy"));
            cookies.add(Cookie.of("legacy", "true"));
            return cookies;
        }
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserWithLegacyLoginHandlerTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(
                    new SuccessAuthenticationScenario("sherlock", Collections.emptyList(), Map.of("email", "sherlock@example.com")),
                    new SuccessAuthenticationScenario("moriarty")));
        }
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserWithLegacyLoginHandlerTest")
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
