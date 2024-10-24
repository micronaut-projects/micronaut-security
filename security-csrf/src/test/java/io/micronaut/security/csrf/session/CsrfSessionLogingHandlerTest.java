package io.micronaut.security.csrf.session;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.*;
import io.micronaut.http.annotation.*;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Property(name = "micronaut.security.authentication", value = "session")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "spec.name", value = "CsrfSessionLogingHandlerTest")
@MicronautTest
class CsrfSessionLogingHandlerTest {

    @Test
    void loginSavesACsrfTokenInSession(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> csrfEcho = HttpRequest.GET("/csrf/echo");
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(csrfEcho));
        assertEquals(HttpStatus.NOT_FOUND, ex.getStatus());

        HttpRequest<?> loginRequest = HttpRequest.POST("/login",Map.of("username",  "sherlock", "password", "password"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        HttpResponse<?> loginRsp = assertDoesNotThrow(() -> client.exchange(loginRequest));
        assertEquals(HttpStatus.OK, loginRsp.getStatus());
        String cookie = loginRsp.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertNotNull(cookie);
        assertTrue(cookie.contains("SESSION="));
        assertTrue(cookie.contains("; HTTPOnly"));
        String sessionId = cookie.split(";")[0].split("=")[1];
        assertNotNull(sessionId);
        HttpRequest<?> csrfEchoRequestWithSession = HttpRequest.GET("/csrf/echo").cookie(Cookie.of("SESSION", sessionId));
        String csrfToken = assertDoesNotThrow(() -> client.retrieve(csrfEchoRequestWithSession));
        assertNotNull(csrfToken);

        PasswordChange form = new PasswordChange("sherlock", "evil");
        HttpRequest<?> passwordChangeRequestNoSessionCookie = HttpRequest.POST("/password/change", form)
                .accept(MediaType.TEXT_HTML)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(passwordChangeRequestNoSessionCookie));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());

        PasswordChangeForm formWithCsrfToken = new PasswordChangeForm("sherlock", "evil", csrfToken);
        HttpRequest<?> passwordChangeRequestWithSessionCookie = HttpRequest.POST("/password/change", formWithCsrfToken)
                .cookie(Cookie.of("SESSION", sessionId))
                .accept(MediaType.TEXT_HTML)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpResponse<String> passwordChangeRequestWithSessionCookieResponse = assertDoesNotThrow(() -> client.exchange(passwordChangeRequestWithSessionCookie, String.class));
        assertEquals(HttpStatus.OK, passwordChangeRequestWithSessionCookieResponse.getStatus());
        Optional<String> htmlOptional = passwordChangeRequestWithSessionCookieResponse.getBody();
        assertTrue(htmlOptional.isPresent());
        assertEquals("sherlock", htmlOptional.get());
    }

    @Requires(property = "spec.name", value = "CsrfSessionLogingHandlerTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = "CsrfSessionLogingHandlerTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChange passwordChangeForm) {
            return passwordChangeForm.username;
        }
    }

    @Serdeable
    record PasswordChange(
            String username,
            String password) {
    }

    @Serdeable
    record PasswordChangeForm(
            String username,
            String password,
            String csrfToken) {
    }

    @Requires(property = "spec.name", value = "CsrfSessionLogingHandlerTest")
    @Controller("/csrf")
    static class CsrfTokenEchoController {

        private final CsrfTokenRepository<HttpRequest<?>> csrfTokenRepository;

        CsrfTokenEchoController(CsrfTokenRepository<HttpRequest<?>> csrfTokenRepository) {
            this.csrfTokenRepository = csrfTokenRepository;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/echo")
        Optional<String> echo(HttpRequest<?> request) {
            return csrfTokenRepository.findCsrfToken(request);
        }
    }
}