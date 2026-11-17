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
import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.http.server.filter.FilterBodyParser;
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

import java.util.concurrent.atomic.AtomicInteger;

import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.CSRF_HEADER;
import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.INVALID_TOKEN;
import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.THROWING_TOKEN;
import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.VALID_TOKEN;
import static io.micronaut.security.csrf.filter.PasswordChangeFixtures.formPost;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CSRF tokens are resolved sequentially in resolver order. The request body is not parsed if the HTTP header already carries a valid token.
 * A token which does not validate, or for which the validator fails, moves the filter on to the next resolver.
 */
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = PasswordChangeFixtures.PROPERTY, value = StringUtils.TRUE)
@Property(name = "spec.name", value = "CsrfFilterSequentialResolutionTest")
@MicronautTest
class CsrfFilterSequentialResolutionTest {

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
        HttpRequest<?> request = formPost("").header(CSRF_HEADER, VALID_TOKEN);
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
        HttpRequest<?> request = formPost("&csrfToken=" + VALID_TOKEN).header(CSRF_HEADER, INVALID_TOKEN);
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
        HttpRequest<?> request = formPost("&csrfToken=" + INVALID_TOKEN).header(CSRF_HEADER, INVALID_TOKEN);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals(1, bodyParserListener.invocations.get());
        assertEquals(2, validator.invocations.get());
    }

    @Test
    void bodyIsParsedWhenValidatorFailsForHeaderToken(@Client("/") HttpClient httpClient,
            CountingCsrfTokenValidator validator,
            CountingFilterBodyParserListener bodyParserListener) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = formPost("&csrfToken=" + VALID_TOKEN).header(CSRF_HEADER, THROWING_TOKEN);
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("sherlock", response.body());
        assertEquals(1, bodyParserListener.invocations.get());
        assertEquals(2, validator.invocations.get());
    }

    @Test
    void requestIsRejectedWhenValidatorFailsForEveryToken(@Client("/") HttpClient httpClient,
            CountingCsrfTokenValidator validator,
            CountingFilterBodyParserListener bodyParserListener) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = formPost("&csrfToken=" + THROWING_TOKEN).header(CSRF_HEADER, THROWING_TOKEN);
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
}
