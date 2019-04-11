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

import io.micronaut.http.HttpParameters;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateSerDes;

import javax.annotation.Nonnull;
import java.util.Objects;

/**
 * Adapts from {@link HttpParameters} to {@link AuthenticationResponse}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class AuthenticationResponseHttpParamsAdapter extends AbstractAuthenticationResponse {

    private final HttpParameters httpParameters;

    /**
     * Constructs an adapter from {@link HttpParameters} to {@link ErrorResponse}.
     * @param httpParameters Http Parameters
     * @param stateSerDes State Serdes
     */
    public AuthenticationResponseHttpParamsAdapter(HttpParameters httpParameters, StateSerDes stateSerDes) {
        super(stateSerDes);
        this.httpParameters = httpParameters;
    }

    @Override
    protected String getStateValue() {
        return httpParameters.get(AuthenticationResponse.KEY_STATE);
    }

    @Nonnull
    @Override
    public String getCode() {
        return Objects.requireNonNull(httpParameters.get(AuthenticationResponse.KEY_CODE));
    }
}
