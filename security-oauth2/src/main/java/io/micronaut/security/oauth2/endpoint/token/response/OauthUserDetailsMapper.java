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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import org.reactivestreams.Publisher;

/**
 * A contract for mapping an OAuth 2.0 token endpoint response to a {@link AuthenticationResponse} object.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface OauthUserDetailsMapper {

    /**
     * A key to be stored in the user details to denote which
     * provider authenticated the user.
     */
    String PROVIDER_KEY = "oauth2Provider";

    /**
     * A key to be stored in the user details to store the
     * access token returned by the provider.
     */
    String ACCESS_TOKEN_KEY = "accessToken";

    /**
     * A key to be stored in the user details to store the
     * refresh token returned by the provider.
     */
    String REFRESH_TOKEN_KEY = "refreshToken";


    /**
     * Convert the token response and state into an authentication response.
     *
     * @param tokenResponse The token response
     * @param state The OAuth state
     * @return The authentication response
     */
    Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state);
}
