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
package io.micronaut.security.csrf.validator;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csrf.repository.CookieCsrfTokenRepository;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.security.csrf.session.SessionCsrfTokenRepository;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RepositoryCsrfTokenValidatorTest {
    private static final String SPEC_NAME = "RepositoryCsrfTokenValidatorTest";
    // without a signature key the HMAC part of the token is empty, a token is <hmac>.<random>
    static final String PRIMARY_TOKEN = ".primary-fixture-not-a-secret";
    static final String SECONDARY_TOKEN = ".secondary-fixture-not-a-secret";

    @Test
    void sessionRepositoryRunsBeforeCookieRepository() {
        try (ApplicationContext context = ApplicationContext.run()) {
            List<Class<?>> repositories = context.getBeansOfType(CsrfTokenRepository.class).stream()
                .<Class<?>>map(Object::getClass)
                .filter(clazz -> clazz == SessionCsrfTokenRepository.class || clazz == CookieCsrfTokenRepository.class)
                .toList();
            assertEquals(List.of(SessionCsrfTokenRepository.class, CookieCsrfTokenRepository.class), repositories);
            assertTrue(SessionCsrfTokenRepository.ORDER < CookieCsrfTokenRepository.ORDER);
        }
    }

    @Test
    void firstRepositoryHoldingATokenIsAuthoritative() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.csrf.repository.cookie.enabled", StringUtils.FALSE,
            "micronaut.security.csrf.repositories.session.enabled", StringUtils.FALSE))) {
            CsrfTokenValidator<HttpRequest<?>> validator = context.getBean(CsrfTokenValidator.class);
            PrimaryRepository primary = context.getBean(PrimaryRepository.class);
            HttpRequest<?> request = HttpRequest.POST("/transfer", "");

            // token found in the first repository must match
            assertTrue(validator.validateCsrfToken(request, PRIMARY_TOKEN));
            // a token only matching a lower precedence repository is rejected
            assertFalse(validator.validateCsrfToken(request, SECONDARY_TOKEN));
            assertFalse(validator.validateCsrfToken(request, ".unknown-fixture-not-a-secret"));

            // when the first repository holds no token, the next repository is consulted
            primary.token = null;
            assertTrue(validator.validateCsrfToken(request, SECONDARY_TOKEN));
            assertFalse(validator.validateCsrfToken(request, PRIMARY_TOKEN));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class PrimaryRepository implements CsrfTokenRepository<HttpRequest<?>> {
        String token = PRIMARY_TOKEN;

        @Override
        @NonNull
        public Optional<String> findCsrfToken(@NonNull HttpRequest<?> request) {
            return Optional.ofNullable(token);
        }

        @Override
        public int getOrder() {
            return -1;
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class SecondaryRepository implements CsrfTokenRepository<HttpRequest<?>> {
        @Override
        @NonNull
        public Optional<String> findCsrfToken(@NonNull HttpRequest<?> request) {
            return Optional.of(SECONDARY_TOKEN);
        }

        @Override
        public int getOrder() {
            return 1;
        }
    }
}
