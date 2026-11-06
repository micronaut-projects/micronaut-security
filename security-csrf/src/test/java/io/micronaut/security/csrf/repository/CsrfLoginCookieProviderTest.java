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
package io.micronaut.security.csrf.repository;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfHmacTokenGenerator;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CsrfLoginCookieProviderTest {

    private static final Map<String, Object> CONFIG = Map.of(
        "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key");

    @Test
    void bothProvideCookieMethodsGoThroughTheOverridableCookieBuilder() {
        try (ApplicationContext context = ApplicationContext.run(CONFIG)) {
            CsrfTokenGenerator<HttpRequest<?>> generator = context.getBean(CsrfTokenGenerator.class);
            CsrfConfiguration configuration = context.getBean(CsrfConfiguration.class);
            CsrfLoginCookieProvider provider = new CsrfLoginCookieProvider(generator, configuration) {
                @Override
                protected Cookie csrfCookie(HttpRequest<?> request, String csrfToken) {
                    return Cookie.of("custom-csrf", csrfToken);
                }
            };
            HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/login", null);
            assertEquals("custom-csrf", provider.provideCookie(request).getName());
            assertEquals("custom-csrf", provider.provideCookie(request, Authentication.build("sherlock")).getName());
        }
    }

    @Test
    void overridingTheOriginalProvideCookieMethodStillCustomizesTheCookieIssuedForTheAuthentication() {
        try (ApplicationContext context = ApplicationContext.run(CONFIG)) {
            CsrfTokenGenerator<HttpRequest<?>> generator = context.getBean(CsrfTokenGenerator.class);
            CsrfConfiguration configuration = context.getBean(CsrfConfiguration.class);
            // a subclass written before 4.18.2 overriding the original public method
            CsrfLoginCookieProvider provider = new CsrfLoginCookieProvider(generator, configuration) {
                @Override
                public Cookie provideCookie(HttpRequest<?> request) {
                    return super.provideCookie(request).path("/custom").httpOnly(false);
                }
            };
            HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/login", null);
            Authentication authentication = Authentication.build("sherlock");

            Cookie cookie = provider.provideCookie(request, authentication);
            assertEquals("/custom", cookie.getPath());
            assertFalse(cookie.isHttpOnly());
            assertEquals(configuration.getCookieName(), cookie.getName());

            // and the value is a token bound to the authenticated user
            String[] hmacAndRandom = cookie.getValue().split("\\" + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR);
            assertEquals(2, hmacAndRandom.length);
            CsrfHmacTokenGenerator<HttpRequest<?>> hmacGenerator = (CsrfHmacTokenGenerator<HttpRequest<?>>) generator;
            assertEquals(hmacGenerator.hmac(request, authentication, hmacAndRandom[1]), hmacAndRandom[0]);
            assertNotEquals(hmacGenerator.hmac(request, Authentication.build("moriarty"), hmacAndRandom[1]), hmacAndRandom[0]);
        }
    }

    @Test
    void defaultProviderIssuesTheConfiguredCookieForTheAuthentication() {
        try (ApplicationContext context = ApplicationContext.run(CONFIG)) {
            CsrfLoginCookieProvider provider = context.getBean(CsrfLoginCookieProvider.class);
            CsrfConfiguration configuration = context.getBean(CsrfConfiguration.class);
            HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/login", null);
            Cookie cookie = provider.provideCookie(request, Authentication.build("sherlock"));
            assertEquals(configuration.getCookieName(), cookie.getName());
            assertFalse(cookie.getValue().isEmpty());
        }
    }
}
