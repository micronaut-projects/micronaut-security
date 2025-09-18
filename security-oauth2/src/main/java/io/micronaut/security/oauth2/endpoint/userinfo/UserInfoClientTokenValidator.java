/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.naming.Named;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.Closeable;
import java.io.IOException;

/**
 * {@link TokenValidator} which uses a remote `UserInfo` endpoint to validate a token.
 */
@Internal
final class UserInfoClientTokenValidator implements Closeable, TokenValidator<HttpRequest<?>>, Named {
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientTokenValidator.class);
    private final HttpClient httpClient;
    private final String path;
    private final String name;

    UserInfoClientTokenValidator(String name, HttpClient httpClient, String path) {
        this.name = name;
        this.httpClient = httpClient;
        this.path = path;
    }

    @Override
    public @NonNull String getName() {
        return name;
    }

    @Override
    public void close() throws IOException {
        httpClient.close();
    }

    @Override
    @NonNull
    public Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
        return Mono.from(httpClient.retrieve(HttpRequest.GET(path).bearerAuth(token),
                Argument.mapOf(String.class, Object.class)))
            .flatMap(m -> {
                Object subject = m.get(Claims.SUBJECT);
                if (subject == null) {
                    return Mono.empty();
                }
                return Mono.just(Authentication.build(subject.toString(), m));
            })
            .onErrorResume(t -> {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(t.getMessage(), t);
                }
                return Mono.empty();
            });
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE - 100;
    }
}
