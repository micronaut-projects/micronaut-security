/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;

import java.util.Optional;

/**
 * API to resolve an {@link AuthorizationServer} based on the issuer url.
 * @author Sergio del Amo
 * @since 4.12.0
 */
@FunctionalInterface
@DefaultImplementation(DefaultAuthorizationServerResolver.class)
public interface AuthorizationServerResolver {
    /**
     *
     * @param issuer OpenID Authorization Server issuer
     * @return Based on substrings of the issuer url, it returns an {@link AuthorizationServer}.
     */
    @NonNull
    Optional<AuthorizationServer> resolve(@NonNull String issuer);
}
