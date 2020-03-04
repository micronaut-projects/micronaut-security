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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.security.authentication.UserDetails;

import javax.annotation.Nonnull;

/**
 * Responsible for converting an OpenID token response to
 * a {@link UserDetails} representing the authenticated user.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@DefaultImplementation(DefaultOpenIdUserDetailsMapper.class)
public interface OpenIdUserDetailsMapper {

    String OPENID_TOKEN_KEY = "openIdToken";

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return A user details object
     */
    @Nonnull
    UserDetails createUserDetails(String providerName,
                                  OpenIdTokenResponse tokenResponse,
                                  OpenIdClaims openIdClaims);
}
