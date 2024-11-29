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

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import jakarta.inject.Singleton;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link io.micronaut.context.annotation.DefaultImplementation} of {@link AuthorizationServerResolver}.
 * Based on substrings of the issuer url it returns an {@link AuthorizationServer}.
 * @author Sergio del Amo
 * @since 4.12.0
 */
@Internal
@Singleton
final class DefaultAuthorizationServerResolver implements AuthorizationServerResolver {
    private static final String ISSUER_PART_OKTA = "okta";
    private static final String ISSUER_PART_ORACLE_CLOUD = "oraclecloud";
    private static final String ISSUER_PART_COGNITO = "cognito";
    private static final String ISSUER_PART_AUTH0 = "auth0";
    private static final String ISSUER_PART_KEYCLOAK = "/auth/realms/";
    private static final Map<String, AuthorizationServer> cache = new ConcurrentHashMap<>();

    @Override
    @NonNull
    public Optional<AuthorizationServer> resolve(@NonNull String issuer) {
        return Optional.ofNullable(cache.computeIfAbsent(issuer, DefaultAuthorizationServerResolver::infer));
    }

    @Nullable
    static AuthorizationServer infer (@NonNull String issuer) {
        if (issuer.contains(ISSUER_PART_ORACLE_CLOUD)) {
            return AuthorizationServer.ORACLE_CLOUD;
        }
        if (issuer.contains(ISSUER_PART_OKTA)) {
            return AuthorizationServer.OKTA;
        }
        if (issuer.contains(ISSUER_PART_COGNITO)) {
            return AuthorizationServer.COGNITO;
        }
        if (issuer.contains(ISSUER_PART_AUTH0)) {
            return AuthorizationServer.AUTH0;
        }
        if (issuer.contains(ISSUER_PART_KEYCLOAK)) {
            return AuthorizationServer.KEYCLOAK;
        }
        return null;
    }
}
