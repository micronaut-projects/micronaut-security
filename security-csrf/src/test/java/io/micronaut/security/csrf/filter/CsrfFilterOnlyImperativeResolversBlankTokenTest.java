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
import io.micronaut.context.annotation.Primary;
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
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.resolver.CsrfTokenResolver;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With the field resolver disabled only imperative {@link CsrfTokenResolver} beans are registered. One which resolves
 * a blank token is skipped: the {@link CsrfTokenValidator} never sees the blank token and the next resolver is consulted.
 */
class CsrfFilterOnlyImperativeResolversBlankTokenTest {
    private static final String SPEC_NAME = "CsrfFilterOnlyImperativeResolversBlankTokenTest";
    private static final String VALID_TOKEN = "valid-csrf-token";

    @Test
    void blankTokenIsRejectedWithoutInvokingTheValidator() {
        try (EmbeddedServer server = startServer();
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            RecordingCsrfTokenValidator validator = server.getApplicationContext().getBean(RecordingCsrfTokenValidator.class);
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.retrieve(formPost()));
            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
            assertTrue(validator.tokens.isEmpty());
        }
    }

    @Test
    void blankTokenDoesNotPreventTheNextResolverFromProvidingAValidToken() {
        try (EmbeddedServer server = startServer();
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            RecordingCsrfTokenValidator validator = server.getApplicationContext().getBean(RecordingCsrfTokenValidator.class);
            CsrfConfiguration csrfConfiguration = server.getApplicationContext().getBean(CsrfConfiguration.class);
            // the blank resolver is ordered first; the header resolver is consulted next
            HttpRequest<?> request = formPost().header(csrfConfiguration.getHeaderName(), VALID_TOKEN);
            assertEquals("payout", client.retrieve(request));
            assertEquals(List.of(VALID_TOKEN), validator.tokens);
        }
    }

    private static EmbeddedServer startServer() {
        return ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.redirect.enabled", StringUtils.FALSE,
            "micronaut.security.csrf.token-resolvers.field.enabled", StringUtils.FALSE,
            "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key"));
    }

    private static MutableHttpRequest<?> formPost() {
        return HttpRequest.POST("/payout", Map.of("amount", "1"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .accept(MediaType.TEXT_PLAIN);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class BlankCsrfTokenResolver implements CsrfTokenResolver<HttpRequest<?>> {
        @Override
        public int getOrder() {
            return Integer.MIN_VALUE;
        }

        @Override
        @NonNull
        public Optional<String> resolveToken(@NonNull HttpRequest<?> request) {
            return Optional.of("  ");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Primary
    @Singleton
    static class RecordingCsrfTokenValidator implements CsrfTokenValidator<HttpRequest<?>> {
        final List<String> tokens = new CopyOnWriteArrayList<>();

        @Override
        public boolean validateCsrfToken(@NonNull HttpRequest<?> request, @NonNull String token) {
            tokens.add(token);
            return VALID_TOKEN.equals(token);
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
