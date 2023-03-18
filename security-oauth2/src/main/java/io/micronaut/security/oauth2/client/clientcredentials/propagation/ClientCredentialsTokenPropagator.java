/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.client.clientcredentials.propagation;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import java.util.Optional;

/**
 * Responsible for retrieving and writing tokens obtained via a client credentials request.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@DefaultImplementation(DefaultClientCredentialsTokenPropagator.class)
public interface ClientCredentialsTokenPropagator extends Ordered {

    /**
     * Writes the token to the request.
     *
     * @param request The {@link MutableHttpRequest} instance
     * @param token A token ( e.g. JWT token, basic auth token...)
     */
    void writeToken(@NonNull MutableHttpRequest<?> request, @NonNull String token);

    /**
     * Attempts to retrieve a token in a request.
     *
     * @param request The request to look for the token in
     * @return An optional token string
     */
    Optional<String> findToken(@NonNull HttpRequest<?> request);
}
