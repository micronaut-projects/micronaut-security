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

package io.micronaut.security.token.paseto.generator.claims;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * @author Utsav Varia
 * @since 3.0
 */
public class PasetoClaimsGenerator implements ClaimsGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(PasetoClaimsGenerator.class);
    private static final String ROLES_KEY = "rolesKey";

    private final TokenConfiguration tokenConfiguration;

    public PasetoClaimsGenerator(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    /**
     * Populates sub claim.
     *
     * @param builder     The Paseto Claims Builder
     * @param authentication Authenticated user's representation.
     */
    protected void populateSub(PasetoClaimsSet.Builder builder, Authentication authentication) {
        builder.claim("sub", authentication.getName()); // sub
    }

    @Override
    public Map<String, Object> generateClaims(Authentication authentication, Integer expiration) {
        // Builder for PasetoClaims
        PasetoClaimsSet.Builder builder = new PasetoClaimsSet.Builder();

        populateSub(builder, authentication);
        authentication.getAttributes().forEach(builder::claim);
        String rolesKey = tokenConfiguration.getRolesName();
        if (!rolesKey.equalsIgnoreCase(TokenConfiguration.DEFAULT_ROLES_NAME)) {
            builder.claim(ROLES_KEY, rolesKey);
        }
        builder.claim(rolesKey, authentication.getRoles());

        PasetoClaimsSet claimsSet = builder.build();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated claim set: {}", claimsSet.getClaims().toString());
        }

        return claimsSet.getClaims();
    }
}
