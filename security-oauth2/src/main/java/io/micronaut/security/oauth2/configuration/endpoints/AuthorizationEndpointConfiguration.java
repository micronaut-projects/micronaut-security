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
package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.authorization.request.Display;
import io.micronaut.security.oauth2.endpoint.authorization.request.Prompt;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Optional;

/**
 * OAuth 2.0. Authorization Endpoint configuration.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
public interface AuthorizationEndpointConfiguration extends EndpointConfiguration {

    /**
     *
     * @return Mechanism to be used for returning Authorization Response parameters from the Authorization Endpoint.
     */
    Optional<String> getResponseMode();

    /**
     *
     * @return Value that determines the authorization processing flow to be used
     */
    @Nonnull
    ResponseType getResponseType();

    /**
     *
     * @return ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    Optional<Display> getDisplay();

    /**
     *
     * @return Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    Optional<Prompt> getPrompt();

    /**
     *
     * @return Maximum Authentication Age.
     */
    Optional<Integer> getMaxAge();

    /**
     *
     * @return End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
     */
    Optional<List<String>> getUiLocales();

    /**
     *
     * @return Requested Authentication Context Class Reference values.
     */
    Optional<List<String>> getAcrValues();
}
