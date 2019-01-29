/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Oauth 2.0. Authorization Request.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Authentication Request</a>
 */
public interface AuthenticationRequest extends AuthorizationEndpointRequestConfiguration {

    String PARAMETER_SCOPE = "scope";
    String PARAMETER_RESPONSE_TYPE = "response_type";
    String PARAMETER_CLIENT_ID = "client_id";
    String PARAMETER_REDIRECT_URI = "redirect_uri";
    String PARAMETER_STATE = "state";
    String PARAMETER_RESPONSE_MODE = "response_mode";
    String PARAMETER_NONCE = "nonce";
    String PARAMETER_DISPLAY = "display";
    String PARAMETER_PROMPT = "prompt";
    String PARAMETER_MAX_AGE = "max_age";
    String PARAMETER_UI_LOCALES = "ui_locales";
    String PARAMETER_ID_TOKEN_HINT = "id_token_hint";
    String PARAMETER_LOGIN_HINT = "login_hint";
    String PARAMETER_ACR_VALUES = "acr_values";

    /**
     *
     * @return OAuth 2.0 Client Identifier valid at the Authorization Server.
     */
    @Nonnull
    String getClientId();

    /**
     *
     * @return Opaque value used to maintain state between the request and the callback.
     */
    @Nullable
    String getState();

    /**
     *
     * @return String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     */
    @Nullable
    String getNonce();

    /**
     *
     * @return Hint to the Authorization Server about the login identifier the End-User might use to log in.
     */
    @Nullable
    String getLoginHint();

    /**
     *
     * @return Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required.
     */
    @Nullable
    String getIdTokenHint();
}
