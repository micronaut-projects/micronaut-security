/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;

import java.util.List;
import java.util.Optional;

/**
 * API to Build/Persist and retrieve a PKCE (Proof Key for Code Exchange).
 * @author Sergio del Amo
 * @since 3.9.0
 */
@DefaultImplementation(DefaultPkceFactory.class)
public interface PkceFactory {
    /**
     * @param request The original request prior redirect
     * @param response The authorization redirect response
     * @param supportedChallengeMethods Challenge methods supported by the authorization server
     * @return A state parameter. An opaque value used to maintain state between the request and the callback.
     */
    @NonNull
    Optional<PkceChallenge> buildChallenge(@NonNull HttpRequest<?> request,
                                           @NonNull MutableHttpResponse<?> response,
                                           @Nullable List<String> supportedChallengeMethods);
}
