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

package io.micronaut.security.oauth2.endpoint.nonce;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;

import javax.annotation.Nonnull;

/**
 * Generates a nonce. A String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken>ID Token Nonce description</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface NonceFactory {

    /**
     * @param request The login request
     * @param response The authorization redirect response
     * @return A nonce. A String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     */
    @Nonnull
    String buildNonce(HttpRequest<?> request, MutableHttpResponse response);
}
