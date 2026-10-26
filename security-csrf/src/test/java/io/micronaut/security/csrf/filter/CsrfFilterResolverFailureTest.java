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
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A {@link FutureCsrfTokenResolver} which completes exceptionally must lead to the CSRF filter rejecting the request, not to a server error.
 */
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "CsrfFilterResolverFailureTest")
@MicronautTest
class CsrfFilterResolverFailureTest {
    static final String VALID_TOKEN = "valid-csrf-token";

    @BeforeEach
    void reset(NullIntolerantCsrfTokenValidator validator, FailingCsrfTokenResolver resolver) {
        validator.invocations.set(0);
        resolver.invocations.set(0);
    }

    @Test
    void failingResolverLeadsToRejectionNotServerError(@Client("/") HttpClient httpClient,
                                                       NullIntolerantCsrfTokenValidator validator,
                                                       FailingCsrfTokenResolver resolver) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertNotEquals(HttpStatus.INTERNAL_SERVER_ERROR, ex.getStatus());
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(1, resolver.invocations.get());
        assertEquals(0, validator.invocations.get());
    }

    @Test
    void validTokenStillPassesWithFailingResolverPresent(@Client("/") HttpClient httpClient,
                                                         NullIntolerantCsrfTokenValidator validator,
                                                         FailingCsrfTokenResolver resolver) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&password=elementary&csrfToken=" + VALID_TOKEN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("sherlock", response.body());
        assertEquals(1, resolver.invocations.get());
        assertEquals(1, validator.invocations.get());
    }

    @Requires(property = "spec.name", value = "CsrfFilterResolverFailureTest")
    @Singleton
    static class FailingCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        @NonNull
        public CompletableFuture<String> resolveToken(@NonNull HttpRequest<?> request) {
            invocations.incrementAndGet();
            return CompletableFuture.failedFuture(new IllegalStateException("malformed body"));
        }
    }

    @Requires(property = "spec.name", value = "CsrfFilterResolverFailureTest")
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

    @Requires(property = "spec.name", value = "CsrfFilterResolverFailureTest")
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
