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

import io.micronaut.context.annotation.Primary;
import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.Optional;

/**
 * Composite Pattern implementation of {@link SessionIdResolver}.
 * @see <a href="https://guides.micronaut.io/latest/micronaut-patterns-composite.html">Composite Pattern</a>
 * @param <T> Request
 */
@Primary
@Singleton
public class CompositeSessionIdResolver<T> implements SessionIdResolver<T> {

    private final List<SessionIdResolver<T>> sessionIdResolvers;

    /**
     *
     * @param sessionIdResolvers List of session id resolvers
     */
    public CompositeSessionIdResolver(List<SessionIdResolver<T>> sessionIdResolvers) {
        this.sessionIdResolvers = sessionIdResolvers;
    }

    @Override
    @NonNull
    public Optional<String> findSessionId(@NonNull T request) {
        return sessionIdResolvers.stream()
                .map(sessionIdResolver -> sessionIdResolver.findSessionId(request))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();
    }
}
