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
package io.micronaut.security.oauth2.endpoint.token.response;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface TokenResponse {

    /**
     * @return The access token issued by the authorization server.
     */
    @Nonnull
    String getAccessToken();

    /**
     *
     * @return The type of the token issued.
     */
    @Nonnull
    String getTokenType();

    /**
     *
     * @return The lifetime in seconds of the access token.
     */
    @Nullable
    Integer getExpiresIn();

    /**
     *
     * @return Scope of the access token.
     */
    @Nullable
    String getScope();

    /**
     * @return The refresh token, which can be used to obtain new access tokens using the same authorization grant.
     */
    @Nullable
    String getRefreshToken();
}
