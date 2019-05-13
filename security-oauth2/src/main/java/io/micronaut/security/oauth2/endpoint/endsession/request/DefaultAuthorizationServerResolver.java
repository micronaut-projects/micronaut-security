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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.validation.Validated;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;
import javax.validation.constraints.NotNull;

/**
 * Default implementation of {@link AuthorizationServerResolver}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Validated
@Singleton
public class DefaultAuthorizationServerResolver implements AuthorizationServerResolver {
    private static final String OKTA = "okta";
    private static final String COGNITO = "cognito";
    private static final String AUTH0 = "auth0";

    @Override
    @Nullable
    public String resolve(@Nonnull @NotNull String issuer) {
        if (issuer.contains(OKTA)) {
            return AuthorizationServer.OKTA.getName();
        } else if (issuer.contains(COGNITO)) {
            return AuthorizationServer.COGNITO.getName();
        } else if (issuer.contains(AUTH0)) {
            return AuthorizationServer.AUTH0.getName();
        }
        return null;
    }
}
