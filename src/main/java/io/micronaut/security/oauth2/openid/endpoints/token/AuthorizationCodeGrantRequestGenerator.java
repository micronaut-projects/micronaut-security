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

package io.micronaut.security.oauth2.openid.endpoints.token;

import io.micronaut.http.HttpRequest;
import javax.annotation.Nonnull;

/**
 * Generates a Token endpoint request for an Authorization code grant.
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
public interface AuthorizationCodeGrantRequestGenerator {

    /**
     *
     * @param code The code received with the authentication response.
     * @return a HTTP Request to the Token Endpoint with Authorization Code Grant payload.
     */
    @Nonnull
    HttpRequest generateRequest(@Nonnull String code);
}
