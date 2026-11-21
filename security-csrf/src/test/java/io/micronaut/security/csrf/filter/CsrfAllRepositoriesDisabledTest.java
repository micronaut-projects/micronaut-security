package io.micronaut.security.csrf.filter;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Disabling every CSRF token repository must not disable CSRF protection: the filter stays in place and rejects requests.
 */
class CsrfAllRepositoriesDisabledTest {
    private static final String SPEC_NAME = "CsrfAllRepositoriesDisabledTest";
    private static final String COOKIE_NAME = "__Host-csrfToken";
    // without a signature key the HMAC part of the token is empty, a token is <hmac>.<random>
    private static final String TOKEN = ".fixture-not-a-secret";

    @Test
    void matchingCookieTokenIsAcceptedWhileTheCookieRepositoryIsEnabled() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config(StringUtils.TRUE));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = httpClient.toBlocking().exchange(request(), String.class);
            assertEquals(HttpStatus.OK, response.getStatus());
        }
    }

    @Test
    void matchingCookieTokenIsRejectedWhenEveryRepositoryIsDisabled() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config(StringUtils.FALSE));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.exchange(request(), String.class));
            // the request is anonymous, so the CSRF rejection is answered with 401
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
        }
    }

    private static Map<String, Object> config(String cookieRepositoryEnabled) {
        Map<String, Object> config = new HashMap<>();
        config.put("spec.name", SPEC_NAME);
        config.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        config.put("micronaut.security.csrf.repositories.cookie.enabled", cookieRepositoryEnabled);
        config.put("micronaut.security.csrf.repositories.session.enabled", StringUtils.FALSE);
        return config;
    }

    private static HttpRequest<?> request() {
        return HttpRequest.POST("/transfer", Map.of("amount", "100"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .header("X-CSRF-TOKEN", TOKEN)
            .cookie(Cookie.of(COOKIE_NAME, TOKEN));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/transfer")
    static class TransferController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Post(consumes = MediaType.APPLICATION_FORM_URLENCODED, produces = MediaType.TEXT_PLAIN)
        String transfer(String amount) {
            return amount;
        }
    }
}
