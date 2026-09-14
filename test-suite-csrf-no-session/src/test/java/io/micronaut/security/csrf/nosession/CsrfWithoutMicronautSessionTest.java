package io.micronaut.security.csrf.nosession;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.reflect.ClassUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.security.csrf.session.SessionCsrfTokenRepository;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * micronaut-security-csrf with cookie authentication and WITHOUT micronaut-session on the classpath.
 * The session-backed CSRF beans must not be loaded, and a form submission that lacks the CSRF cookie
 * must be rejected by the CSRF filter instead of failing with a {@link NoClassDefFoundError}.
 */
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "spec.name", value = "CsrfWithoutMicronautSessionTest")
@MicronautTest
class CsrfWithoutMicronautSessionTest {
    private static final String CSRF_SESSION_POPULATOR = "io.micronaut.security.csrf.session.CsrfSessionPopulator";
    private static final String JWT_COOKIE_PREFIX = "JWT=";
    private static final String CSRF_TOKEN = "abcdef";

    @Inject
    BeanContext beanContext;

    @Test
    void micronautSessionIsNotOnTheClasspath() {
        assertFalse(ClassUtils.isPresent("io.micronaut.session.Session", null));
        assertFalse(ClassUtils.isPresent("io.micronaut.session.http.SessionForRequest", null));
        assertFalse(ClassUtils.isPresent("io.micronaut.security.session.SessionPopulator", null));
    }

    @Test
    void sessionBackedCsrfBeansAreNotLoadedWithoutMicronautSession() {
        assertFalse(beanContext.containsBean(SessionCsrfTokenRepository.class));
        assertTrue(beanContext.getBeanDefinitions(CsrfTokenRepository.class).stream()
                .map(BeanDefinition::getName)
                .noneMatch(SessionCsrfTokenRepository.class.getName()::equals));
        assertTrue(beanContext.getAllBeanDefinitions().stream()
                .map(BeanDefinition::getName)
                .noneMatch(CSRF_SESSION_POPULATOR::equals));
    }

    @Test
    void formPostWithoutCsrfCookieIsRejectedInsteadOfFailingWithServerError(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpResponse<?> loginRsp = assertDoesNotThrow(() -> client.exchange(loginRequest));
        assertEquals(HttpStatus.OK, loginRsp.getStatus());
        String jwt = loginRsp.getHeaders().getAll(HttpHeaders.SET_COOKIE).stream()
                .filter(cookie -> cookie.startsWith(JWT_COOKIE_PREFIX))
                .map(cookie -> cookie.split(";")[0].substring(JWT_COOKIE_PREFIX.length()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("JWT cookie not set on login"));

        // Authenticated via the JWT cookie, a CSRF token is supplied in the form and in the header but the CSRF cookie is missing.
        // The cookie repository finds nothing, so the composite repository falls through to the next repository.
        Map<String, String> form = Map.of("username", "sherlock", "password", "evil", "csrfToken", CSRF_TOKEN);
        HttpRequest<?> authenticatedRequest = HttpRequest.POST("/password/change", form)
                .cookie(Cookie.of("JWT", jwt))
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(authenticatedRequest, String.class));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());

        HttpRequest<?> anonymousRequest = HttpRequest.POST("/password/change", form)
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(anonymousRequest, String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
    }

    @Requires(property = "spec.name", value = "CsrfWithoutMicronautSessionTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = "CsrfWithoutMicronautSessionTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(String username) {
            return username;
        }
    }
}
