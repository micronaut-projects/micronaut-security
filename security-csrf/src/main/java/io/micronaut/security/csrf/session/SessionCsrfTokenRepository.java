/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.session;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Implementation of {@link CsrfTokenRepository} that retrieves the CSRF token from an HTTP session using the key defined in {@link CsrfConfiguration#getHttpSessionName()}.
 * This repository takes precedence over {@link io.micronaut.security.csrf.repository.CookieCsrfTokenRepository}: when the request carries an HTTP session holding a CSRF token,
 * the session token is the one validated against the token supplied in the request.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(classes = HttpRequest.class)
@Requires(beans = CsrfConfiguration.class)
@Requires(property = CsrfConfiguration.PREFIX + ".repositories.session.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
public class SessionCsrfTokenRepository implements CsrfTokenRepository<HttpRequest<?>> {
    /**
     * The order of this repository. It runs before {@link io.micronaut.security.csrf.repository.CookieCsrfTokenRepository}.
     * @since 4.18.2
     */
    public static final int ORDER = -100;

    private final CsrfConfiguration csrfConfiguration;

    /**
     *
     * @param csrfConfiguration CSRF Configuration
     */
    public SessionCsrfTokenRepository(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    @NonNull
    public Optional<String> findCsrfToken(@NonNull HttpRequest<?> request) {
        return SessionForRequest.find(request)
                .flatMap(session -> session.get(csrfConfiguration.getHttpSessionName(), String.class));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
