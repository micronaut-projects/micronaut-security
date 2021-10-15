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
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.Claims;
import dev.paseto.jpaseto.Paseto;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.AbstractTokenAuthenticationFactory;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Default implementation of {@link PasetoAuthenticationFactory}.
 *
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class DefaultPasetoAuthenticationFactory extends AbstractTokenAuthenticationFactory<Paseto> implements PasetoAuthenticationFactory {

    /**
     *
     * @param tokenConfiguration Token Configuration
     * @param rolesFinder Utility to retrieve roles from token claims
     */
    public DefaultPasetoAuthenticationFactory(TokenConfiguration tokenConfiguration, RolesFinder rolesFinder) {
        super(tokenConfiguration, rolesFinder);
    }

    @Override
    public Optional<Authentication> createAuthentication(Paseto token) {
        final Claims attributes = token.getClaims();
        if (attributes == null) {
            return Optional.empty();
        }
        return super.createAuthentication(attributes);
    }
}
