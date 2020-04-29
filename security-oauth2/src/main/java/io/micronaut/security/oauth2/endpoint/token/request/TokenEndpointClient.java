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

package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Responsible for sending requests to a token endpoint.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@DefaultImplementation(DefaultTokenEndpointClient.class)
public interface TokenEndpointClient {

    /**
     * @param requestContext The token request context
     * @param <G> The token request grant or body
     * @param <R> The token response type
     * @return a HTTP Request to the Token Endpoint with Authorization Code Grant payload.
     */
    @NonNull
    <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext);
}
