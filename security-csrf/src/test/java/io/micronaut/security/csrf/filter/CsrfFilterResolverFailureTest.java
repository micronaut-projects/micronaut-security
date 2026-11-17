/*
 * Copyright 2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.csrf.filter.PasswordChangeFixtures.CountingCsrfTokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.VALID_TOKEN;
import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.formPost;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A {@link FutureCsrfTokenResolver} which completes exceptionally must lead to the CSRF filter rejecting the request, not to a server error.
 */
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = PasswordChangeFixtures.PROPERTY, value = StringUtils.TRUE)
@Property(name = "spec.name", value = "CsrfFilterResolverFailureTest")
@MicronautTest
class CsrfFilterResolverFailureTest {

    @BeforeEach
    void reset(CountingCsrfTokenValidator validator, FailingCsrfTokenResolver resolver) {
        validator.invocations.set(0);
        resolver.invocations.set(0);
    }

    @Test
    void failingResolverLeadsToRejectionNotServerError(@Client("/") HttpClient httpClient,
            CountingCsrfTokenValidator validator,
            FailingCsrfTokenResolver resolver) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = formPost("");
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(1, resolver.invocations.get());
        assertEquals(0, validator.invocations.get());
    }

    @Test
    void validTokenStillPassesWithFailingResolverPresent(@Client("/") HttpClient httpClient,
            CountingCsrfTokenValidator validator,
            FailingCsrfTokenResolver resolver) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = formPost("&csrfToken=" + VALID_TOKEN);
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
}
