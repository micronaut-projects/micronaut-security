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
import java.util.Map;
import java.util.Objects;

/**
 * Adapts from a Map to {@link AuthenticationResponse}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class AuthenticationResponseMapAdapter extends AbstractAuthenticationResponse {

    private final Map<String, String> formFields;

    /**
     * Constructs an adapter from a Map to {@link AuthenticationResponse}.
     *
     * @param formFields A Map encapsulating the form url encoded payload.
     * @param stateSerDes The state serdes
     */
    public AuthenticationResponseMapAdapter(Map<String, String> formFields, StateSerDes stateSerDes) {
        super(stateSerDes);
        this.formFields = formFields;
    }

    @Nullable
    @Override
    public String getStateValue() {
        return getStringValue(AuthenticationResponse.KEY_STATE);
    }

    @Nonnull
    @Override
    public String getCode() {
        return Objects.requireNonNull(getStringValue(AuthenticationResponse.KEY_CODE));
    }

    private String getStringValue(String keyname) {
        if (formFields != null && formFields.containsKey(keyname)) {
            return formFields.get(keyname);
        }
        return null;
    }
}
