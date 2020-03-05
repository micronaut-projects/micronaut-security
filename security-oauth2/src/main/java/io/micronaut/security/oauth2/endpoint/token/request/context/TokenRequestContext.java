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
package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;

/**
 * Represents the context of a token endpoint request.
 *
 * @param <G> The grant or body of the request
 * @param <R> The response type
 */
public interface TokenRequestContext<G, R extends TokenResponse> {

    /**
     * @return The grant or body of the request
     */
    G getGrant();

    /**
     * @return The response argument
     */
    Argument<R> getResponseType();

    /**
     * @return The error response argument
     */
    Argument<?> getErrorResponseType();

    /**
     * @return The media type of the grant or body
     */
    MediaType getMediaType();

    /**
     * @return The endpoint of which to send the request
     */
    SecureEndpoint getEndpoint();

    /**
     * @return The client configuration
     */
    OauthClientConfiguration getClientConfiguration();
}
