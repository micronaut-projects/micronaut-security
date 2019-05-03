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

package io.micronaut.security.oauth2.endpoint.token.response.validation;

import com.nimbusds.jwt.JWT;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;

import java.util.Optional;

/**
 * Validates a ID Token Access Response.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OpenIdTokenResponseValidator {

    /**
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * @return true if the ID Token access response is considered valid
     */
    Optional<JWT> validate(OauthClientConfiguration clientConfiguration,
                           OpenIdProviderMetadata openIdProviderMetadata,
                           OpenIdTokenResponse openIdTokenResponse);
}
