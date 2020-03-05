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

import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * OAuth 2.0 Authentication Response.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Authentication Response</a>
 *
 * @since 1.2.0
 * @author Sergio del Amo
 */
public interface AuthorizationResponse {

    String KEY_CODE = "code";
    String KEY_STATE = "state";

    /**
     * @return The state parameter in the callback request
     */
    @Nullable
    State getState();

    /**
     * @return An authorization code which the client will later exchange for an access token.
     */
    @Nonnull
    String getCode();


    /**
     * @return The authorization callback request
     */
    @Nonnull
    HttpRequest<?> getCallbackRequest();
}
