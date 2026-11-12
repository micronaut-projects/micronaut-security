package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
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
import io.micronaut.http.server.filter.FilterBodyParser;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CSRF tokens are resolved sequentially in resolver order. The request body is not parsed if the HTTP header already carries a valid token.
 */
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "CsrfFilterSequentialResolutionTest")
@MicronautTest
class CsrfFilterSequentialResolutionTest {
    static final String VALID_TOKEN = "valid-csrf-token";
    static final String INVALID_TOKEN = "invalid-csrf-token";
    static final String CSRF_HEADER = "X-CSRF-TOKEN";

    @BeforeEach
    void reset(CountingCsrfTokenValidator validator, CountingFilterBodyParserListener bodyParserListener) {
        validator.invocations.set(0);
        bodyParserListener.invocations.set(0);
    }

    @Test
    void bodyIsNotParsedWhenHeaderTokenIsValid(@Client("/") HttpClient httpClient,
                                               CountingCsrfTokenValidator validator,
                                               CountingFilterBodyParserListener bodyParserListener) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .header(CSRF_HEADER, VALID_TOKEN)
                .accept(MediaType.TEXT_HTML);
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("sherlock", response.body());
        assertEquals(0, bodyParserListener.invocations.get());
        assertEquals(1, validator.invocations.get());
    }

    @Test
    void bodyIsParsedWhenHeaderTokenIsInvalid(@Client("/") HttpClient httpClient,
                                              CountingCsrfTokenValidator validator,
                                              CountingFilterBodyParserListener bodyParserListener) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=" + VALID_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .header(CSRF_HEADER, INVALID_TOKEN)
                .accept(MediaType.TEXT_HTML);
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("sherlock", response.body());
        assertEquals(1, bodyParserListener.invocations.get());
        assertEquals(2, validator.invocations.get());
    }

    @Test
    void requestIsRejectedWhenNeitherTokenIsValid(@Client("/") HttpClient httpClient,
                                                  CountingCsrfTokenValidator validator,
                                                  CountingFilterBodyParserListener bodyParserListener) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=" + INVALID_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .header(CSRF_HEADER, INVALID_TOKEN)
                .accept(MediaType.TEXT_HTML);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(1, bodyParserListener.invocations.get());
        assertEquals(2, validator.invocations.get());
    }

    @Requires(property = "spec.name", value = "CsrfFilterSequentialResolutionTest")
    @Singleton
    static class CountingFilterBodyParserListener implements BeanCreatedEventListener<FilterBodyParser> {
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        public FilterBodyParser onCreated(@NonNull BeanCreatedEvent<FilterBodyParser> event) {
            FilterBodyParser delegate = event.getBean();
            return request -> {
                invocations.incrementAndGet();
                return delegate.parseBody(request);
            };
        }
    }

    @Requires(property = "spec.name", value = "CsrfFilterSequentialResolutionTest")
    @Primary
    @Singleton
    static class CountingCsrfTokenValidator implements CsrfTokenValidator<HttpRequest<?>> {
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        public boolean validateCsrfToken(@NonNull HttpRequest<?> request, @NonNull String token) {
            invocations.incrementAndGet();
            return VALID_TOKEN.equals(token);
        }
    }

    @Requires(property = "spec.name", value = "CsrfFilterSequentialResolutionTest")
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
