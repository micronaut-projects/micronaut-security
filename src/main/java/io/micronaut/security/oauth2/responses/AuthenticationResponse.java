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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Oauth 2.0 Authentication Response.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Authentication Response</a>
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
public interface AuthenticationResponse {

    String KEY_CODE = "code";
    String KEY_STATE = "state";

    /**
     * If the initial request contained a state parameter, the response must also include the exact value from the request. The client will be using this to associate this response with the initial request.
     * @return state parameter.
     */
    @Nullable
    String getState();

    /**
     *
     * @return An authorization code which the client will later exchange for an access token.
     */
    @Nonnull
    String getCode();
}
