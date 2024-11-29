/*
 * Copyright 2017-2023 original authors
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

import io.micronaut.core.annotation.NonNull;
import java.util.Optional;

/**
 * Authorization Servers.
 * @author Sergio del Amo
 * @since 3.2.0
 */
public enum AuthorizationServer {
    OKTA,
    ORACLE_CLOUD,
    COGNITO,
    KEYCLOAK,
    AUTH0,
    MICROSOFT;

    /**
     * @param issuer Issuer url
     * @return An Authorization Server if it could be inferred based on the contents of the issuer or empty if not
     * @deprecated Use {@link AuthorizationServerResolver} instead
    */
    @Deprecated
    @NonNull
    public static Optional<AuthorizationServer> infer(@NonNull String issuer) {
        return Optional.ofNullable(DefaultAuthorizationServerResolver.infer(issuer));
    }
}
