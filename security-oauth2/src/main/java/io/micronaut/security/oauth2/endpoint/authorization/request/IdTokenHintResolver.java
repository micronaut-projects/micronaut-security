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

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Resolves a Id Token Hint. A Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token id_token_hint description</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface IdTokenHintResolver {

    /**
     * @param request The originating request
     * @return A IdTokenHint.
     */
    @NonNull
    String resolve(HttpRequest<?> request);
}
