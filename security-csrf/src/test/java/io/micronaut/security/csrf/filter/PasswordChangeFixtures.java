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

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Beans shared by the CSRF filter tests which post a password change form. A test enables them with the property {@value #PROPERTY}.
 */
final class PasswordChangeFixtures {
    static final String PROPERTY = "csrf.fixtures.password-change";
    static final String VALID_TOKEN = "valid-csrf-token";
    static final String INVALID_TOKEN = "invalid-csrf-token";
    static final String THROWING_TOKEN = "throwing-csrf-token";
    static final String CSRF_HEADER = "X-CSRF-TOKEN";

    private PasswordChangeFixtures() {
    }

    /**
     * @param extraFormFields Form fields appended to the username and password, for example {@code &csrfToken=abc}; may be empty
     * @return A form POST to the password change endpoint
     */
    static MutableHttpRequest<String> formPost(String extraFormFields) {
        return HttpRequest.POST("/password/change", "username=sherlock&password=elementary" + extraFormFields)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
    }

    /**
     * Counts its invocations. Accepts {@link #VALID_TOKEN}, throws for {@link #THROWING_TOKEN} and for a null token, and rejects any other token.
     */
    @Requires(property = PROPERTY, value = "true")
    @Primary
    @Singleton
    static class CountingCsrfTokenValidator implements CsrfTokenValidator<HttpRequest<?>> {
        final AtomicInteger invocations = new AtomicInteger();

        @Override
        public boolean validateCsrfToken(@NonNull HttpRequest<?> request, @NonNull String token) {
            invocations.incrementAndGet();
            if (token == null) {
                throw new NullPointerException("token must not be null");
            }
            if (THROWING_TOKEN.equals(token)) {
                throw new IllegalStateException("test-fixture validator failure");
            }
            return VALID_TOKEN.equals(token);
        }
    }

    @Requires(property = PROPERTY, value = "true")
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
