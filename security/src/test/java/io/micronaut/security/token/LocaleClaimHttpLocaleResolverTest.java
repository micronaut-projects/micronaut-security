/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token;

import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.server.util.locale.HttpAbstractLocaleResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolutionConfiguration;
import io.micronaut.http.server.util.locale.RequestLocaleResolver;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocaleClaimHttpLocaleResolverTest {

    private final LocaleClaimHttpLocaleResolver resolver = new LocaleClaimHttpLocaleResolver(
            new TestHttpLocaleResolutionConfiguration(),
            ConversionService.SHARED
    );

    @Test
    void resolvesLocaleClaimFromRequestAuthentication() {
        MutableHttpRequest<?> request = authenticatedRequest(Map.of(ProfileClaims.CLAIM_LOCALE, "es-ES"));

        Optional<Locale> locale = resolver.resolve(request);

        assertEquals(Optional.of(Locale.of("es", "ES")), locale);
    }

    @Test
    void resolvesLocaleClaimWhenClaimValueIsAlreadyLocale() {
        MutableHttpRequest<?> request = authenticatedRequest(Map.of(ProfileClaims.CLAIM_LOCALE, Locale.FRENCH));

        Optional<Locale> locale = resolver.resolve(request);

        assertEquals(Optional.of(Locale.FRENCH), locale);
    }

    @Test
    void returnsEmptyWhenAuthenticationIsMissing() {
        Optional<Locale> locale = resolver.resolve(HttpRequest.GET("/"));

        assertTrue(locale.isEmpty());
    }

    @Test
    void returnsEmptyWhenLocaleClaimIsMissing() {
        MutableHttpRequest<?> request = authenticatedRequest(Map.of("name", "Sergio"));

        Optional<Locale> locale = resolver.resolve(request);

        assertTrue(locale.isEmpty());
    }

    @Test
    void returnsEmptyWhenLocaleClaimCannotBeConverted() {
        MutableHttpRequest<?> request = authenticatedRequest(Map.of(ProfileClaims.CLAIM_LOCALE, List.of("es", "ES")));

        Optional<Locale> locale = resolver.resolve(request);

        assertTrue(locale.isEmpty());
    }

    @Test
    void orderedAfterSessionAndCookieLocaleResolversAndBeforeRequestLocaleResolver() {
        assertTrue(resolver.getOrder() > HttpAbstractLocaleResolver.ORDER);
        assertTrue(resolver.getOrder() < RequestLocaleResolver.ORDER);
    }

    private static MutableHttpRequest<?> authenticatedRequest(Map<String, Object> attributes) {
        MutableHttpRequest<?> request = HttpRequest.GET("/");
        request.setAttribute(SecurityFilter.AUTHENTICATION, Authentication.build("sergio", List.of(), attributes));
        return request;
    }

    private static final class TestHttpLocaleResolutionConfiguration implements HttpLocaleResolutionConfiguration {

        @Override
        public Optional<String> getSessionAttribute() {
            return Optional.empty();
        }

        @Override
        public Optional<String> getCookieName() {
            return Optional.empty();
        }

        @Override
        public boolean isHeader() {
            return false;
        }

        @Override
        public Optional<Locale> getFixed() {
            return Optional.empty();
        }

        @Override
        public Locale getDefaultLocale() {
            return Locale.ENGLISH;
        }
    }
}
