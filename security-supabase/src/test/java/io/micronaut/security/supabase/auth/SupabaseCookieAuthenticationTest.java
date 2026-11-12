package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.supabase.auth.SignupRequest;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import io.micronaut.supabase.auth.SupabaseAuthRequests.TokenRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.Principal;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Cookie authentication mode backed by Supabase: login stores the Supabase tokens in the cookies, the access
 * token cookie authenticates requests, refresh rotates both cookies and logout revokes the Supabase session.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "spec.name", value = "SupabaseCookieAuthenticationTest")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseCookieAuthenticationTest implements TestPropertyProvider {
    private static final String EMAIL = "cookie-test@example.com";
    private static final String PASSWORD = "correct-horse-battery";
    private static final String ACCESS_COOKIE = "JWT";
    private static final String REFRESH_COOKIE = "JWT_REFRESH_TOKEN";

    @Inject
    SupabaseAuthClient supabase;

    @Inject
    @Client("/")
    HttpClient httpClient;

    private String userId;

    @Override
    public @NonNull Map<String, String> getProperties() {
        Map<String, String> properties = new HashMap<>(Supabase.getProperties());
        properties.put("micronaut.security.token.jwt.signatures.secret.supabase.secret", Supabase.jwtSecret());
        properties.put("micronaut.security.token.jwt.signatures.secret.supabase.jws-algorithm", "HS256");
        return properties;
    }

    @BeforeAll
    void signUp() {
        Map<String, Object> session = supabase.signup(null, new SignupRequest(EMAIL, null, PASSWORD, null, null, null, null, null)).body();
        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) session.get("user");
        userId = (String) user.get("id");
    }

    @Test
    void loginStoresTheSupabaseTokensInTheCookies() {
        HttpResponse<?> response = login(PASSWORD);

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/", response.getHeaders().get(HttpHeaders.LOCATION));
        Map<String, SetCookie> cookies = cookies(response);
        SetCookie access = cookies.get(ACCESS_COOKIE);
        SetCookie refresh = cookies.get(REFRESH_COOKIE);
        assertEquals(userId, claim(access.value(), "sub"), "access cookie should be the Supabase JWT of the user");
        assertEquals(Supabase.JWT_ISSUER, claim(access.value(), "iss"));
        assertEquals(3600L, access.maxAge(), "access cookie max-age should follow Supabase expires_in");
        assertTrue(refresh.value().length() > 0);
        assertNotEquals(3, refresh.value().split("\\.").length, "refresh cookie should be the opaque Supabase refresh token");
        assertTrue(access.httpOnly());
        assertTrue(refresh.httpOnly());
    }

    @Test
    void theAccessTokenCookieAuthenticatesRequests() {
        SetCookie access = cookies(login(PASSWORD)).get(ACCESS_COOKIE);

        HttpResponse<String> response = client().exchange(HttpRequest.GET("/secured").cookie(access.toCookie()), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(userId, response.body());
    }

    @Test
    void securedEndpointRejectsRequestsWithoutTheCookie() {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client().exchange(HttpRequest.GET("/secured"), String.class));

        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    @Test
    void wrongPasswordRedirectsToTheFailureUrlWithoutCookies() {
        HttpResponse<?> response = login("wrong-password");

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/login/authFailed", response.getHeaders().get(HttpHeaders.LOCATION));
        assertTrue(cookies(response).isEmpty());
    }

    @Test
    void refreshRotatesBothCookies() {
        Map<String, SetCookie> initial = cookies(login(PASSWORD));

        HttpResponse<?> response = client().exchange(HttpRequest.POST("/oauth/access_token",
                Map.of("grant_type", "refresh_token", "refresh_token", initial.get(REFRESH_COOKIE).value()))
            .cookie(initial.get(REFRESH_COOKIE).toCookie()));

        assertTrue(response.getStatus() == HttpStatus.OK || response.getStatus() == HttpStatus.SEE_OTHER, "status " + response.getStatus());
        Map<String, SetCookie> rotated = cookies(response);
        assertNotEquals(initial.get(REFRESH_COOKIE).value(), rotated.get(REFRESH_COOKIE).value(), "Supabase rotates the refresh token");
        assertEquals(userId, claim(rotated.get(ACCESS_COOKIE).value(), "sub"));
        assertEquals(3600L, rotated.get(ACCESS_COOKIE).maxAge());
    }

    /**
     * GoTrue tolerates reuse of a refresh token within {@code GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL}
     * (10 seconds by default), so a just-rotated token is not a reliable negative case; an unknown one is.
     */
    @Test
    void refreshWithAnUnknownRefreshTokenIsAnInvalidGrant() {
        String refreshToken = "not-a-supabase-refresh-token";

        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client().exchange(HttpRequest.POST("/oauth/access_token", Map.of("grant_type", "refresh_token", "refresh_token", refreshToken))));

        assertEquals(HttpStatus.BAD_REQUEST, e.getStatus());
        assertTrue(e.getResponse().getBody(String.class).orElse("").contains("invalid_grant"));
    }

    @Test
    void logoutClearsTheCookiesAndRevokesTheSupabaseSession() throws InterruptedException {
        Map<String, SetCookie> initial = cookies(login(PASSWORD));

        HttpResponse<?> response = client().exchange(HttpRequest.POST("/logout", "")
            .cookie(initial.get(ACCESS_COOKIE).toCookie())
            .cookie(initial.get(REFRESH_COOKIE).toCookie()));

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        Map<String, SetCookie> cleared = cookies(response);
        assertEquals("", cleared.get(ACCESS_COOKIE).value());
        assertEquals(0L, cleared.get(ACCESS_COOKIE).maxAge());
        assertEquals("", cleared.get(REFRESH_COOKIE).value());
        assertEquals(0L, cleared.get(REFRESH_COOKIE).maxAge());
        String refreshToken = initial.get(REFRESH_COOKIE).value();
        for (int attempt = 0; attempt < 50; attempt++) {
            if (refreshAtSupabase(refreshToken).isEmpty()) {
                return;
            }
            Thread.sleep(100);
        }
        fail("the Supabase session should have been revoked on logout");
    }

    private HttpResponse<?> login(String password) {
        return client().exchange(HttpRequest.POST("/login", Map.of("username", EMAIL, "password", password)));
    }

    /**
     * Runs the refresh-token grant directly against Supabase, as the refreshed access token on success.
     */
    private Optional<String> refreshAtSupabase(String refreshToken) {
        try {
            var response = supabase.token("refresh_token", new TokenRequest(refreshToken, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null, null));
            return response.getStatus().getCode() < 400 && response.body() != null
                ? Optional.ofNullable(response.body().accessToken())
                : Optional.empty();
        } catch (HttpClientResponseException e) {
            return Optional.empty();
        }
    }

    private BlockingHttpClient client() {
        return httpClient.toBlocking();
    }

    /**
     * A parsed {@code Set-Cookie} header.
     */
    record SetCookie(String name, String value, Long maxAge, boolean httpOnly) {
        Cookie toCookie() {
            return Cookie.of(name, value);
        }

        static SetCookie parse(String header) {
            String[] parts = header.split(";");
            String[] nameValue = parts[0].trim().split("=", 2);
            Long maxAge = null;
            boolean httpOnly = false;
            for (int i = 1; i < parts.length; i++) {
                String attribute = parts[i].trim();
                if (attribute.regionMatches(true, 0, "Max-Age=", 0, 8)) {
                    maxAge = Long.parseLong(attribute.substring(8));
                } else if (attribute.equalsIgnoreCase("HttpOnly")) {
                    httpOnly = true;
                }
            }
            return new SetCookie(nameValue[0], nameValue.length > 1 ? nameValue[1] : "", maxAge, httpOnly);
        }
    }

    private static Map<String, SetCookie> cookies(HttpResponse<?> response) {
        Map<String, SetCookie> cookies = new HashMap<>();
        for (String header : response.getHeaders().getAll(HttpHeaders.SET_COOKIE)) {
            SetCookie cookie = SetCookie.parse(header);
            cookies.put(cookie.name(), cookie);
        }
        return cookies;
    }

    private static String claim(String jwt, String name) {
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
        String key = "\"" + name + "\":\"";
        int start = payload.indexOf(key);
        if (start < 0) {
            return null;
        }
        start += key.length();
        return payload.substring(start, payload.indexOf('"', start));
    }

    @Requires(property = "spec.name", value = "SupabaseCookieAuthenticationTest")
    @Controller("/secured")
    static class SecuredController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            return principal.getName();
        }
    }
}
