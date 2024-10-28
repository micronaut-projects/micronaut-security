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
package io.micronaut.security.session;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.session.Session;
import jakarta.inject.Singleton;

/**
 * Default Implementation of {@link SessionPopulator}. It adds the {@link Authentication} object to the session with the key {@link SecurityFilter#AUTHENTICATION}.
 * @param <T> Request
 */
@Singleton
@Internal
final class DefaultSessionPopulator<T> implements SessionPopulator<T> {
    /**
     * Adds the {@link Authentication} object to the session with the key {@link SecurityFilter#AUTHENTICATION}.
     * @param request  The request
     * @param authentication The authenticated user.
     * @param session The session
     */
    @Override
    public void populateSession(T request, @NonNull Authentication authentication, @NonNull Session session) {
        session.put(SecurityFilter.AUTHENTICATION, authentication);
    }
}
