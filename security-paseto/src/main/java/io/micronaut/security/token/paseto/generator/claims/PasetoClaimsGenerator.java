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

import io.micronaut.context.env.Environment;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.runtime.ApplicationConfiguration;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class PasetoClaimsGenerator implements ClaimsGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(PasetoClaimsGenerator.class);
    private static final String ROLES_KEY = "rolesKey";

    private final TokenConfiguration tokenConfiguration;
    private final ClaimsAudienceProvider claimsAudienceProvider;
    private final PasetoIdGenerator pasetoIdGenerator;
    private final String appName;

    /**
     * @param tokenConfiguration       Token Configuration
     * @param claimsAudienceProvider   Generator which creates unique JWT ID
     * @param pasetoIdGenerator        Provider which identifies the recipients that the JWT is intended for.
     * @param applicationConfiguration The application configuration
     */
    public PasetoClaimsGenerator(TokenConfiguration tokenConfiguration,
                                 @Nullable ClaimsAudienceProvider claimsAudienceProvider,
                                 @Nullable PasetoIdGenerator pasetoIdGenerator,
                                 @Nullable ApplicationConfiguration applicationConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
        this.claimsAudienceProvider = claimsAudienceProvider;
        this.pasetoIdGenerator = pasetoIdGenerator;
        this.appName = applicationConfiguration != null ? applicationConfiguration.getName().orElse(Environment.MICRONAUT) : Environment.MICRONAUT;
    }

    /**
     * Populates sub claim.
     *
     * @param builder        The Paseto Claims Builder
     * @param authentication Authenticated user's representation.
     */
    protected void populateSub(PasetoClaimsSet.Builder builder, Authentication authentication) {
        builder.subject(authentication.getName()); // sub
    }

    /**
     * Populates iss claim.
     *
     * @param builder The Claims Builder
     */
    protected void populateIss(PasetoClaimsSet.Builder builder) {
        if (appName != null) {
            builder.issuer(appName); // iss
        }
    }

    /**
     * Populates aud claim.
     *
     * @param builder The Claims Builder
     */
    protected void populateAud(PasetoClaimsSet.Builder builder) {
        if (claimsAudienceProvider != null) {
            builder.audience(claimsAudienceProvider.audience()); // aud
        }
    }

    /**
     * Populates exp claim.
     *
     * @param builder    The Claims Builder
     * @param expiration expiration time in seconds
     */
    protected void populateExp(PasetoClaimsSet.Builder builder, @Nullable Integer expiration) {
        if (expiration != null) {
            LOG.debug("Setting expiration to {}", expiration);
            builder.expiration(Instant.now().plus(expiration, ChronoUnit.SECONDS)); // exp
        }
    }

    /**
     * Populates nbf claim.
     *
     * @param builder The Claims Builder
     */
    protected void populateNbf(PasetoClaimsSet.Builder builder) {
        builder.notBefore(Instant.now()); // nbf
    }

    /**
     * Populates iat claim.
     *
     * @param builder The Claims Builder
     */
    protected void populateIat(PasetoClaimsSet.Builder builder) {
        builder.issuedAt(Instant.now()); // iat
    }

    /**
     * Populates jti claim.
     *
     * @param builder The Claims Builder
     */
    protected void populateJti(PasetoClaimsSet.Builder builder) {
        if (pasetoIdGenerator != null) {
            builder.tokenId(pasetoIdGenerator.generateJtiClaim()); // jti
        }
    }

    @Override
    public Map<String, Object> generateClaims(Authentication authentication, Integer expiration) {
        PasetoClaimsSet.Builder builder = new PasetoClaimsSet.Builder();

        populateIat(builder);
        populateExp(builder, expiration);
        populateJti(builder);
        populateIss(builder);
        populateAud(builder);
        populateNbf(builder);
        populateWithAuthentication(builder, authentication);

        //TODO:  Add Support for footer in token

        PasetoClaimsSet claimsSet = builder.build();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated claim set:");
            LOG.debug("{");
            claimsSet.getClaims().forEach((key, value) -> LOG.debug("\t{} : {}", key, value));
            LOG.debug("}");
        }
        return claimsSet.getClaims();
    }

    /**
     * Populates Claims with Authentication object.
     *
     * @param builder        the Claims Builder
     * @param authentication Authenticated user's representation.
     */
    protected void populateWithAuthentication(PasetoClaimsSet.Builder builder, Authentication authentication) {
        populateSub(builder, authentication);
        authentication.getAttributes().forEach(builder::claim);
        String rolesKey = tokenConfiguration.getRolesName();
        if (!rolesKey.equalsIgnoreCase(TokenConfiguration.DEFAULT_ROLES_NAME)) {
            builder.claim(ROLES_KEY, rolesKey);
        }
        builder.claim(rolesKey, authentication.getRoles());
    }
}
