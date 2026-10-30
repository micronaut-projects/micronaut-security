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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A {@link FutureCsrfTokenResolver} which fails, either by returning a failed future, by returning a null future or by throwing, must not make
 * the CSRF filter answer with a server error. The request is rejected unless another resolver provides a valid token.
 */
class CsrfFilterFailingTokenResolverTest {
    private static final String SPEC_NAME = "CsrfFilterFailingTokenResolverTest";

    @Test
    void failingResolversRejectTheRequestInsteadOfServerError() {
        try (EmbeddedServer server = startServer();
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.retrieve(formPost()));
            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        }
    }

    @Test
    void failingResolversDoNotPreventAnotherResolverFromAcceptingAValidToken() {
        try (EmbeddedServer server = startServer();
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            CsrfConfiguration csrfConfiguration = server.getApplicationContext().getBean(CsrfConfiguration.class);
            CsrfTokenGenerator<HttpRequest<?>> generator = server.getApplicationContext().getBean(CsrfTokenGenerator.class);
            String csrfToken = generator.generateCsrfToken(formPost());
            HttpRequest<?> request = formPost()
                .header(csrfConfiguration.getHeaderName(), csrfToken)
                .cookie(Cookie.of(csrfConfiguration.getCookieName(), csrfToken));
            assertEquals("payout", client.retrieve(request));
        }
    }

    @Test
    void bodyOverMaxRequestSizeIsNotReportedAsUnauthorized() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.server.max-request-size", "64",
                "micronaut.security.redirect.enabled", StringUtils.FALSE,
                "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<?> request = HttpRequest.POST("/payout", "amount=" + "1".repeat(1024))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_PLAIN);
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
            assertEquals(HttpStatus.REQUEST_ENTITY_TOO_LARGE, exception.getStatus());
        }
    }

    private static EmbeddedServer startServer() {
        return ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.redirect.enabled", StringUtils.FALSE,
            "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key"));
    }

    private static MutableHttpRequest<?> formPost() {
        return HttpRequest.POST("/payout", Map.of("amount", "1"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .accept(MediaType.TEXT_PLAIN);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class FailedFutureCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
        @Override
        @NonNull
        public CompletableFuture<String> resolveToken(@NonNull HttpRequest<?> request) {
            return CompletableFuture.failedFuture(new IllegalStateException("test-fixture resolver failure"));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class NullFutureCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
        @Override
        @NonNull
        @SuppressWarnings("java:S2637")
        public CompletableFuture<String> resolveToken(@NonNull HttpRequest<?> request) {
            return null;
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class ThrowingCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
        @Override
        @NonNull
        public CompletableFuture<String> resolveToken(@NonNull HttpRequest<?> request) {
            throw new IllegalStateException("test-fixture resolver failure");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class FormController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/payout")
        String payout(@Body Map<String, String> form) {
            return "payout";
        }
    }
}
