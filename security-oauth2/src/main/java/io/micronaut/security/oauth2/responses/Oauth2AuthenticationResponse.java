/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.responses;

import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateSerDes;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * OAuth 2.0 authorization response.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class Oauth2AuthenticationResponse extends AbstractAuthenticationResponse {

    private String state;
    private String code;

    /**
     * Construct authorization response object.
     *
     * @param stateSerDes The state serdes
     */
    public Oauth2AuthenticationResponse(StateSerDes stateSerDes) {
        super(stateSerDes);
    }

    /**
     * If the initial request contained a state parameter, the response must also include the exact value from the request. The client will be using this to associate this response with the initial request.
     * @return state parameter.
     */
    @Nullable
    @Override
    public String getStateValue() {
        return state;
    }

    /**
     * After the state has been retrieved, further calls to this method will
     * not be reflected in the execution of {@link #getState()}.
     *
     * @param state Set state.
     */
    public void setState(@Nullable String state) {
        this.state = state;
    }

    /**
     *
     * @return An authorization code which the client will later exchange for an access token.
     */
    @Nonnull
    public String getCode() {
        return code;
    }

    /**
     * Set an authorization code.
     * @param code authorization code.
     */
    public void setCode(@Nonnull String code) {
        this.code = code;
    }
}
