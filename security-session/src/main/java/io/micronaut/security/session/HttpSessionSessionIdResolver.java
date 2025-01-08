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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.session.Session;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Implementation of {@link SessionIdResolver} that returns {@link Session#getId()} if an HTTP session  is associated with the request.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(property = SessionIdResolver.PREFIX + ".httpsession-id.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
final class HttpSessionSessionIdResolver implements SessionIdResolver<HttpRequest<?>> {
    @Override
    @NonNull
    public Optional<String> findSessionId(@NonNull HttpRequest<?> request) {
        return SessionForRequest.find(request).map(Session::getId);
    }
}
