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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;

/**
 * JWT Claims Validator for ID Token.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#HybridIDTValidation2">ID Token Validation</a>
 *
 * @since 1.2.0
 * @author Sergio del Amo
 */
public interface OpenIdClaimsValidator {

    /**
     * @param claims ID Token Claims
     * @param clientConfiguration OAuth 2.0 Client Configuration
     * @param providerMetadata OpenID Connect provider metadata
     * @return Whether the JWT Claims pass validation or not.
     */
    boolean validate(OpenIdClaims claims,
                     OauthClientConfiguration clientConfiguration,
                     OpenIdProviderMetadata providerMetadata);
}
