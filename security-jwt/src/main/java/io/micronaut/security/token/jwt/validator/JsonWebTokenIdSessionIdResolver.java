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
package io.micronaut.security.token.jwt.validator;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.session.SessionIdResolver;
import jakarta.inject.Singleton;

import java.util.Optional;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;
import static io.micronaut.security.token.Claims.TOKEN_ID;

/**
 * Implementation of {@link SessionIdResolver} that returns the jti claim JWT ID if a JWT token  is associated with the request.
 *
 * @since 4.11.0
 * @author  Sergio del Amo
 */
@Requires(property = SessionIdResolver.PREFIX + ".jwt-id.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Requires(classes = HttpRequest.class)
@Requires(bean = JsonWebTokenParser.class)
@Singleton
@Internal
final class JsonWebTokenIdSessionIdResolver implements SessionIdResolver<HttpRequest<?>> {
    private final JsonWebTokenParser<?> jsonWebTokenParser;

    public JsonWebTokenIdSessionIdResolver(JsonWebTokenParser<?> jsonWebTokenParser) {
        this.jsonWebTokenParser = jsonWebTokenParser;
    }

    @Override
    @NonNull
    public Optional<String> findSessionId(@NonNull HttpRequest<?> request) {
        return request.getAttribute(TOKEN, String.class)
                .flatMap(jsonWebTokenParser::parseClaims)
                .flatMap(claims -> Optional.ofNullable(claims.get(TOKEN_ID)).map(Object::toString));
    }
}
