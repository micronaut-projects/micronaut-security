/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.endpoints.introspection;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import org.reactivestreams.Publisher;

/**
 * Given a {@link IntrospectionRequest} generates a {@link IntrospectionResponse}.
 * @see <a href="https://tools.ietf.org/html/rfc7662">RFC7662</a>
 * @author Sergio del Amo
 * @since 2.1.0
 */
public interface IntrospectionProcessor {

    /**
     *
     * @param introspectionRequest A parameter representing the token along with optional parameters representing additional context
     * @param httpRequest HTTP Request
     * @return Introspection Response
     */
    @NonNull
    Publisher<IntrospectionResponse> introspect(@NonNull IntrospectionRequest introspectionRequest,
                                                @NonNull HttpRequest<?> httpRequest);

    /**
     *
     * @param authentication The authentication
     * @param httpRequest HTTP Request
     * @return Introspection Response
     */
    @NonNull
    Publisher<IntrospectionResponse> introspect(@NonNull Authentication authentication,
                                                @NonNull HttpRequest<?> httpRequest);
}
