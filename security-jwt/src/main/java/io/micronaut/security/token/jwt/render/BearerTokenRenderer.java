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
package io.micronaut.security.token.jwt.render;

import io.micronaut.http.HttpHeaderValues;
import io.micronaut.security.authentication.UserDetails;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Singleton;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */

@Singleton
public class BearerTokenRenderer implements TokenRenderer {

    private final String BEARER_TOKEN_TYPE = HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER;

    @Override
    public AccessRefreshToken render(Integer expiresIn, String accessToken, @Nullable String refreshToken) {
        return new AccessRefreshToken(accessToken, refreshToken, BEARER_TOKEN_TYPE, expiresIn);
    }

    @Override
    public AccessRefreshToken render(UserDetails userDetails, Integer expiresIn, String accessToken, @Nullable String refreshToken) {
        return new BearerAccessRefreshToken(userDetails.getUsername(), userDetails.getRoles(), expiresIn, accessToken, refreshToken, BEARER_TOKEN_TYPE);
    }
}
