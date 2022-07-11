/*
 * Copyright 2017-2021 original authors
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
    COGNITO,
    KEYCLOAK,
    KEYCLOAK_17,
    AUTH0;

    private static final String ISSUER_PART_OKTA = "okta";
    private static final String ISSUER_PART_COGNITO = "cognito";
    private static final String ISSUER_PART_AUTH0 = "auth0";
    private static final String ISSUER_PART_KEYCLOAK = "/auth/realms/";
    private static final String ISSUER_PART_KEYCLOAK_17 = "/realms/";

    /**
     * @param issuer Issuer url
     * @return An Authorization Server if it could be inferred based on the contents of the issuer or empty if not
     */
    @NonNull
    public static Optional<AuthorizationServer> infer(@NonNull String issuer) {
        if (issuer.contains(ISSUER_PART_OKTA)) {
            return Optional.of(AuthorizationServer.OKTA);
        }
        if (issuer.contains(ISSUER_PART_COGNITO)) {
            return Optional.of(AuthorizationServer.COGNITO);
        }
        if (issuer.contains(ISSUER_PART_AUTH0)) {
            return Optional.of(AuthorizationServer.AUTH0);
        }
        if (issuer.contains(ISSUER_PART_KEYCLOAK)) {
            return Optional.of(AuthorizationServer.KEYCLOAK);
        }
        if (issuer.contains(ISSUER_PART_KEYCLOAK_17)) {
            return Optional.of(AuthorizationServer.KEYCLOAK_17);
        }
        return Optional.empty();
    }
}
