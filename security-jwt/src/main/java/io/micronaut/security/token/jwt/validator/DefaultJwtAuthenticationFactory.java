/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.AbstractTokenAuthenticationFactory;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Singleton;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Extracts the JWT claims and uses the {@link AuthenticationJWTClaimsSetAdapter} to construction an {@link Authentication} object.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
public class DefaultJwtAuthenticationFactory extends AbstractTokenAuthenticationFactory<JWT> implements JwtAuthenticationFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultJwtAuthenticationFactory.class);

    /**
     *
     * @param tokenConfiguration Token Configuration
     * @param rolesFinder Utility to retrieve roles from token claims
     */
    public DefaultJwtAuthenticationFactory(TokenConfiguration tokenConfiguration,
                                           RolesFinder rolesFinder) {
        super(tokenConfiguration, rolesFinder);
    }

    @Override
    public Optional<Authentication> createAuthentication(JWT token) {
        try {
            final JWTClaimsSet claimSet = token.getJWTClaimsSet();
            if (claimSet == null) {
                return Optional.empty();
            }
            return createAuthentication(claimSet.getClaims());
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ParseException creating authentication", e);
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param claimSet JWT Claims
     * @return the username defined by {@link TokenConfiguration#getNameKey()} ()} or the sub claim.
     * @deprecated Use {@link AbstractTokenAuthenticationFactory#usernameForClaims(Claims)} instead.
     * @throws ParseException might be thrown parsing claims
     */
    @Deprecated
    protected Optional<String> usernameForClaims(JWTClaimsSet claimSet) throws ParseException {
        return super.usernameForClaims(new MapClaims(claimSet.getClaims()));
    }


}
