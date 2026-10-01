package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Primary;
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
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A custom {@link CsrfTokenValidator} which does not tolerate a null token must never be invoked when the request carries no CSRF token.
 */
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "CsrfFilterNullTokenValidatorTest")
@MicronautTest
class CsrfFilterNullTokenValidatorTest {
    static final String VALID_TOKEN = "valid-csrf-token";

    @BeforeEach
    void resetValidator(NullIntolerantCsrfTokenValidator validator) {
        validator.invocations.set(0);
    }

    @Test
    void validatorIsNotInvokedWhenNoTokenIsPresent(@Client("/") HttpClient httpClient,
                                                   NullIntolerantCsrfTokenValidator validator) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertNotEquals(HttpStatus.INTERNAL_SERVER_ERROR, ex.getStatus());
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(0, validator.invocations.get());
    }

    @Test
    void validatorIsNotInvokedWhenTokenIsBlank(@Client("/") HttpClient httpClient,
                                               NullIntolerantCsrfTokenValidator validator) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=%20%20")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(0, validator.invocations.get());
    }

    @Test
    void invalidTokenIsRejected(@Client("/") HttpClient httpClient,
                                NullIntolerantCsrfTokenValidator validator) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=invalid")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(1, validator.invocations.get());
    }

    @Test
    void validTokenPasses(@Client("/") HttpClient httpClient,
                          NullIntolerantCsrfTokenValidator validator) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=" + VALID_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("sherlock", response.body());
        assertEquals(1, validator.invocations.get());
    }

    @Requires(property = "spec.name", value = "CsrfFilterNullTokenValidatorTest")
    @Primary
    @Singleton
    static class NullIntolerantCsrfTokenValidator implements CsrfTokenValidator<HttpRequest<?>> {
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        public boolean validateCsrfToken(@NonNull HttpRequest<?> request, @NonNull String token) {
            invocations.incrementAndGet();
            if (token == null) {
                throw new NullPointerException("token must not be null");
            }
            return VALID_TOKEN.equals(token);
        }
    }

    @Requires(property = "spec.name", value = "CsrfFilterNullTokenValidatorTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChangeForm passwordChangeForm) {
            return passwordChangeForm.username();
        }
    }

    @Serdeable
    record PasswordChangeForm(String username, String password, String csrfToken) {
    }
}
