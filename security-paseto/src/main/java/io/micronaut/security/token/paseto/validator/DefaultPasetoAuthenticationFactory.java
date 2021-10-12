/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.Claims;
import dev.paseto.jpaseto.Paseto;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class DefaultPasetoAuthenticationFactory implements PasetoAuthenticationFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultPasetoAuthenticationFactory.class);

    private final TokenConfiguration tokenConfiguration;
    private final RolesFinder rolesFinder;

    public DefaultPasetoAuthenticationFactory(TokenConfiguration tokenConfiguration, RolesFinder rolesFinder) {
        this.tokenConfiguration = tokenConfiguration;
        this.rolesFinder = rolesFinder;
    }

    @Override
    public Optional<Authentication> createAuthentication(Paseto token) {
        try {
            final Claims attributes = token.getClaims();
            if (attributes == null) {
                return Optional.empty();
            }
            return usernameForClaims(attributes).map(username ->
                    Authentication.build(username,
                            rolesFinder.resolveRoles(attributes),
                            attributes));
        } catch (Exception e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Exception while creating authentication", e);
            }
        }
        return Optional.empty();
    }

    private Optional<String> usernameForClaims(Claims claims) {
        String username = claims.get(tokenConfiguration.getNameKey(), String.class);
        if (username == null) {
            return Optional.ofNullable(claims.getSubject());
        }
        return Optional.of(username);
    }
}
