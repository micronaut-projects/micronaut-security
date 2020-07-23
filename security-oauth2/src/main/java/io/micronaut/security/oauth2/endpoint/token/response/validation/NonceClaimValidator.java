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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Singleton;

/**
 * Responsible for validating the nonce claim.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class NonceClaimValidator {

    /**
     * @param claims ID Token Claims
     * @param clientConfiguration OAuth 2.0 Client Configuration
     * @param providerMetadata OpenID Connect provider metadata
     * @param nonce The nonce value
     * @return Whether the JWT Claims pass validation or not.
     */
    public boolean validate(OpenIdClaims claims,
                            OauthClientConfiguration clientConfiguration,
                            OpenIdProviderMetadata providerMetadata,
                            @Nullable String nonce) {
        String nonceClaim = claims.getNonce();
        if (nonceClaim != null && nonce != null) {
            return nonceClaim.equals(nonce);
        } else {
            return nonceClaim == null && nonce == null;
        }
    }
}
