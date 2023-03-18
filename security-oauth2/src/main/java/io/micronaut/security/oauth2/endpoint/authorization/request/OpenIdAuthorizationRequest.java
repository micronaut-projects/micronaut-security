/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.http.MutableHttpResponse;
import java.util.List;
import java.util.Optional;

/**
 * The OpenID extensions to the standard OAuth 2.0 authorization request.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Authorization Request</a>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface OpenIdAuthorizationRequest extends AuthorizationRequest {

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
     * @param response The authorization redirect response
     * @return String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     */
    Optional<String> getNonce(MutableHttpResponse response);

    /**
     * @return Hint to the Authorization Server about the login identifier the End-User might use to log in.
     */
    Optional<String> getLoginHint();

    /**
     * @return Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required.
     */
    Optional<String> getIdTokenHint();

    /**
     * @return Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.
     */
    Optional<String> getResponseMode();

    /**
     * @return ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    Optional<Display> getDisplay();

    /**
     * @return Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    Optional<Prompt> getPrompt();

    /**
     * @return Maximum Authentication Age.
     */
    Optional<Integer> getMaxAge();

    /**
     * @return End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
     */
    Optional<List<String>> getUiLocales();

    /**
     * @return Requested Authentication Context Class Reference values.
     */
    Optional<List<String>> getAcrValues();
}
