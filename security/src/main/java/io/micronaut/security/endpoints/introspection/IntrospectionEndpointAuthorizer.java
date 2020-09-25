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

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.http.HttpRequest;
import org.reactivestreams.Publisher;

/**
 * Contract to implement the authorization of the introspection endpoint.
 * RFC7662: To prevent token scanning attacks, the introspection endpoint MUST also require some form of authorization to access this endpoint.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7662">RFC7662</a>
 * @author Sergio del Amo
 * @since 2.1.0
 */
@FunctionalInterface
public interface IntrospectionEndpointAuthorizer {

    /**
     *
     * @param introspectionRequest A parameter representing the token along with optional parameters representing additional context
     * @param httpRequest HTTP Request
     * @return Whether the introspection request is authorized
     */
    Publisher<Boolean> isAuthorized(@NonNull IntrospectionRequest introspectionRequest,
                                    @NonNull HttpRequest<?> httpRequest);
}
