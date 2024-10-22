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
package io.micronaut.security.csrf.resolver;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.ServerHttpRequest;
import io.micronaut.http.body.ByteBody;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Resolves a CSRF token from a form-urlencoded body using the {@link ServerHttpRequest#byteBody()} API.
 *
 * @since 2.0.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = "micronaut.security.csrf.token-resolvers.field.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
class FieldCsrfTokenResolver implements ReactiveCsrfTokenResolver<HttpRequest<?>> {
    private final CsrfConfiguration csrfConfiguration;

    FieldCsrfTokenResolver(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    @Singleton
    public Publisher<String> resolveToken(HttpRequest<?> request) {
        if (request instanceof ServerHttpRequest<?> serverHttpRequest) {
            return resolveToken(serverHttpRequest);
        }
        return Publishers.empty();
    }

    private Publisher<String> resolveToken(ServerHttpRequest<?> request) {
        return Mono.fromFuture(request.byteBody().split(ByteBody.SplitBackpressureMode.FASTEST).buffer())
            .map(bb -> bb.toString(request.getCharacterEncoding()))
            .map(this::extractCsrfTokenFromAFormUrlEncodedString)
            .flatMap(opt -> opt.map(Mono::just).orElseGet(Mono::empty));
    }

    private Optional<String> extractCsrfTokenFromAFormUrlEncodedString(String body) {
        final String[] arr = body.split("&");
        final String prefix = csrfConfiguration.getFieldName() + "=";
        for (String s : arr) {
            if (s.startsWith(prefix)) {
                return Optional.of(s.substring(prefix.length()));
            }
        }
        return Optional.empty();
    }
}
