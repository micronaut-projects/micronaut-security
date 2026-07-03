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
package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.AbstractAuthenticationMapper;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collections;

@Internal
@Singleton
class NimbusAuthenticationMapper extends AbstractAuthenticationMapper {
    private static final Logger LOG = LoggerFactory.getLogger(NimbusAuthenticationMapper.class);

    NimbusAuthenticationMapper(RolesFinder rolesFinder) {
        super(rolesFinder);
    }

    @Override
    public @Nullable Authentication of(@NonNull String token) {
        // A JWT must have at least two dots (JWS) or four dots (JWE)
        if (!(token.contains(".") && token.indexOf('.', token.indexOf('.') + 1) != -1)) {
            return null;
        }
        try {
            JWT jwt = JWTParser.parse(token);
            Claims claims = jwt.getJWTClaimsSet() == null
                ? new MapClaims(Collections.emptyMap())
                : new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
            return of(claims);
        } catch (ParseException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Failed to parse JWT: {}", e.getMessage());
            }
            return null;
        }
    }
}
