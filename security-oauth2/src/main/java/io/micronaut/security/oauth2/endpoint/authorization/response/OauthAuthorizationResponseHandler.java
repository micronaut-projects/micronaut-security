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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import org.reactivestreams.Publisher;

/**
 * Responsible for handling the authorization callback response
 * from an OAuth 2.0 provider.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@DefaultImplementation(DefaultOauthAuthorizationResponseHandler.class)
public interface OauthAuthorizationResponseHandler {

    /**
     * Receives the authorization response and ultimately
     * returns the authentication response.
     *
     * @param authorizationResponse The authorization response
     * @param clientConfiguration The client configuration
     * @param authenticationMapper The authetncation mapper
     * @param tokenEndpoint The token endpoint
     * @return An authentication response publisher
     */
    Publisher<AuthenticationResponse> handle(AuthorizationResponse authorizationResponse,
                                             OauthClientConfiguration clientConfiguration,
                                             OauthAuthenticationMapper authenticationMapper,
                                             SecureEndpoint tokenEndpoint);
}
