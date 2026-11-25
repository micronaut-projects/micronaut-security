/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token.macaroons;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.AbstractTokenAuthenticationFactory;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Default {@link MacaroonAuthenticationFactory}.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Singleton
public class DefaultMacaroonAuthenticationFactory extends AbstractTokenAuthenticationFactory<MacaroonAuthenticationContext> implements MacaroonAuthenticationFactory {

    /**
     * @param tokenConfiguration Token configuration
     * @param rolesFinder Roles finder
     */
    public DefaultMacaroonAuthenticationFactory(TokenConfiguration tokenConfiguration,
                                                RolesFinder rolesFinder) {
        super(tokenConfiguration, rolesFinder);
    }

    @Override
    public Optional<Authentication> createAuthentication(MacaroonAuthenticationContext context) {
        return createAuthentication(context.getClaims());
    }
}
