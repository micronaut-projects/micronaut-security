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
import java.util.List;

/**
 * Encapsulates the parts of the Oauth 2.0. Authorization Request that are configurable.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Authentication Request</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface AuthorizationEndpointRequestConfiguration {
    /**
     *
     * @return OAuth 2.0 scopes.
     */
    @Nonnull
    List<String> getScopes();

    /**
     * @return OAuth 2.0 Response Type value that determines the authorization processing flow to be used, including what parameters are returned from the endpoints used.
     */
    @Nonnull
    String getResponseType();

    /**
     * @return Redirection URI to which the response will be sent.
     */
    @Nullable
    String getRedirectUri();

    /**
     *
     * @return Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.
     */
    @Nullable
    String getResponseMode();

    /**
     *
     * @return ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    @Nullable
    Display getDisplay();

    /**
     *
     * @return Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    @Nullable
    Prompt getPrompt();

    /**
     *
     * @return Maximum Authentication Age.
     */
    @Nullable
    Integer getMaxAge();

    /**
     *
     * @return End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
     */
    @Nullable
    List<String> getUiLocales();

    /**
     *
     * @return Requested Authentication Context Class Reference values.
     */
    @Nullable
    List<String> getAcrValues();
}
