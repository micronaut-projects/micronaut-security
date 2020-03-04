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

package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.http.HttpRequest;

import javax.annotation.Nonnull;

/**
 * Resolves a LoginHint. Hint to the Authorization Server about the login identifier the End-User might use to log in.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken>ID Token login_hint description</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface LoginHintResolver {

    /**
     * Hint to the authorization server about the login identifier the user might use to log in.
     *
     * @param request The originating request
     * @return The login hint
     */
    @Nonnull
    String resolve(HttpRequest<?> request);
}
