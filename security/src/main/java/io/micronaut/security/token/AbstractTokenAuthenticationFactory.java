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
package io.micronaut.security.token;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

/**
 * Abstract implementation of {@link TokenAuthenticationFactory} which creates an authentication for a set of claims.
 * @author Sergio del Amo
 * @since 3.2.0
 * @param <T> The Token type. e.g JWT or Paseto
 */
public abstract class AbstractTokenAuthenticationFactory<T> implements TokenAuthenticationFactory<T> {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractTokenAuthenticationFactory.class);

    private final TokenConfiguration tokenConfiguration;
    private final RolesFinder rolesFinder;

    /**
     *
     * @param tokenConfiguration Token Configuration
     * @param rolesFinder Utility to retrieve roles from token claims
     */
    public AbstractTokenAuthenticationFactory(TokenConfiguration tokenConfiguration,
                                              RolesFinder rolesFinder) {
        this.tokenConfiguration = tokenConfiguration;
        this.rolesFinder = rolesFinder;
    }

    /**
     *
     * @param claims Claims
     * @return the username defined by {@link TokenConfiguration#getNameKey()} ()} or the sub claim.
     */
    @NonNull
    protected Optional<String> usernameForClaims(@NonNull Claims claims) {
        Object username = claims.get(tokenConfiguration.getNameKey());
        if (username != null) {
            return Optional.of(username.toString());
        }
        Object sub = claims.get(TokenConfiguration.DEFAULT_NAME_KEY);
        if (sub == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sub.toString());
    }

    /**
     *
     * @param attributes Claims
     * @return {@link Authentication} object based on the user claims
     */
    protected Optional<Authentication> createAuthentication(@NonNull Map<String, Object> attributes) {
        return usernameForClaims(new MapClaims(attributes)).map(username ->
                Authentication.build(username,
                        rolesFinder.resolveRoles(attributes),
                        attributes));
    }
}
