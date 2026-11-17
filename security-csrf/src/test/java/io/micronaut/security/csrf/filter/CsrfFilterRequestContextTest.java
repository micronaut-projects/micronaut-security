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

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.csrf.resolver.CsrfTokenResolver;
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A {@link FutureCsrfTokenResolver} may complete on a thread which carries the context of a different request. The
 * resolvers consulted afterwards, the validator and the rejection handler must still see the request being filtered.
 */
class CsrfFilterRequestContextTest {

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void asynchronousFallbackPreservesRequestContext(boolean validToken) throws Exception {
        HttpRequest<?> request = HttpRequest.POST("/payout", "amount=1")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpRequest<?> workerRequest = HttpRequest.GET("/another-request");
        CompletableFuture<String> pending = new CompletableFuture<>();
        AtomicInteger resolverInvocations = new AtomicInteger();
        AtomicInteger validatorInvocations = new AtomicInteger();
        FutureCsrfTokenResolver<HttpRequest<?>> delayedResolver = new FutureCsrfTokenResolver<>() {
            @Override
            public CompletableFuture<String> resolveToken(HttpRequest<?> resolvedRequest) {
                assertSame(request, resolvedRequest);
                assertSame(request, ServerRequestContext.currentRequest().orElse(null));
                return pending;
            }

            @Override
            public int getOrder() {
                return -200;
            }
        };
        CsrfTokenResolver<HttpRequest<?>> fallbackResolver = resolvedRequest -> {
            resolverInvocations.incrementAndGet();
            assertSame(request, resolvedRequest);
            assertSame(request, ServerRequestContext.currentRequest().orElse(null));
            return Optional.of(validToken ? "test-fixture-valid-token" : "test-fixture-invalid-token");
        };
        CsrfFilter filter = new CsrfFilter(new CsrfFilterConfigurationProperties(), List.of(delayedResolver),
            List.of(fallbackResolver), (resolvedRequest, token) -> {
                validatorInvocations.incrementAndGet();
                assertSame(request, resolvedRequest);
                assertSame(request, ServerRequestContext.currentRequest().orElse(null));
                return "test-fixture-valid-token".equals(token);
            }, (rejectedRequest, failure) -> {
                assertSame(request, rejectedRequest);
                assertSame(request, ServerRequestContext.currentRequest().orElse(null));
                return HttpResponse.unauthorized();
            });

        Supplier<CompletableFuture<@Nullable HttpResponse<?>>> applyFilter = () -> filter.csrfFilter(request);
        CompletableFuture<@Nullable HttpResponse<?>> result = ServerRequestContext.with(request, applyFilter);
        assertNotNull(result);
        assertFalse(result.isDone());
        assertEquals(0, resolverInvocations.get());
        assertEquals(0, validatorInvocations.get());
        assertTrue(ServerRequestContext.currentRequest().isEmpty());

        try (var executor = Executors.newSingleThreadExecutor()) {
            executor.submit(() -> ServerRequestContext.with(workerRequest, () -> {
                // Completion runs the fallback on a thread carrying a different request's context.
                assertTrue(pending.complete(null));
                assertSame(workerRequest, ServerRequestContext.currentRequest().orElse(null));
            })).get(5, TimeUnit.SECONDS);
        }

        HttpResponse<?> response = result.get(5, TimeUnit.SECONDS);
        if (validToken) {
            assertNull(response);
        } else {
            assertNotNull(response);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatus());
        }
        assertEquals(1, resolverInvocations.get());
        assertEquals(1, validatorInvocations.get());
        assertTrue(ServerRequestContext.currentRequest().isEmpty());
    }
}
