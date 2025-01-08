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

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.session.SessionPopulator;
import io.micronaut.session.Session;
import jakarta.inject.Singleton;

/**
 * Populates the session with a CSRF token.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> Request
 */
@Singleton
@Internal
final class CsrfSessionPopulator<T> implements SessionPopulator<T> {
    private final CsrfConfiguration csrfConfiguration;
    private final CsrfTokenGenerator<T> csrfTokenGenerator;

    /**
     *
     * @param csrfConfiguration CSRF Configuration
     * @param csrfTokenGenerator CSRF Token Generator
     */
    public CsrfSessionPopulator(CsrfConfiguration csrfConfiguration,
                                CsrfTokenGenerator<T> csrfTokenGenerator) {
        this.csrfConfiguration = csrfConfiguration;
        this.csrfTokenGenerator = csrfTokenGenerator;
    }

    @Override
    public void populateSession(T request,
                                Authentication authentication,
                                Session session) {
        session.put(csrfConfiguration.getHttpSessionName(), csrfTokenGenerator.generateCsrfToken(request));
    }
}
