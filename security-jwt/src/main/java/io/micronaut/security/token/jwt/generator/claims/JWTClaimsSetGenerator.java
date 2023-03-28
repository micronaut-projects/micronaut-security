/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.generator.claims;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.env.Environment;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.runtime.ApplicationConfiguration;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class JWTClaimsSetGenerator implements ClaimsGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(JWTClaimsSetGenerator.class);
    private static final String ROLES_KEY = "rolesKey";

    private final TokenConfiguration tokenConfiguration;
    private final JwtIdGenerator jwtIdGenerator;
    private final ClaimsAudienceProvider claimsAudienceProvider;
    private final String appName;

    /**
     * @param tokenConfiguration       Token Configuration
     * @param jwtIdGenerator           Generator which creates unique JWT ID
     * @param claimsAudienceProvider   Provider which identifies the recipients that the JWT is intended for.
     * @param applicationConfiguration The application configuration
     */
    public JWTClaimsSetGenerator(TokenConfiguration tokenConfiguration,
                                 @Nullable JwtIdGenerator jwtIdGenerator,
                                 @Nullable ClaimsAudienceProvider claimsAudienceProvider,
                                 @Nullable ApplicationConfiguration applicationConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
        this.jwtIdGenerator = jwtIdGenerator;
        this.claimsAudienceProvider = claimsAudienceProvider;
        this.appName = applicationConfiguration != null ? applicationConfiguration.getName().orElse(Environment.MICRONAUT) : Environment.MICRONAUT;
    }

    /**
     * @param authentication Authenticated user's representation.
     * @param expiration  expiration time in seconds
     * @return The authentication claims
     */
    @Override
    public Map<String, Object> generateClaims(Authentication authentication, @Nullable Integer expiration) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        populateIat(builder);
        populateExp(builder, expiration);
        populateJti(builder);
        populateIss(builder);
        populateAud(builder);
        populateNbf(builder);
        populateWithAuthentication(builder, authentication);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated claim set: {}", builder.build().toJSONObject());
        }
        return builder.build().getClaims();
    }

    /**
     * Populates iss claim.
     *
     * @param builder The Claims Builder
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.1">iss (Issuer) Claim</a>
     */
    protected void populateIss(JWTClaimsSet.Builder builder) {
        if (appName != null) {
            builder.issuer(appName); // iss
        }
    }

    /**
     * Populates sub claim.
     *
     * @param builder     The Claims Builder
     * @param authentication Authenticated user's representation.
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.2">sub (Subject) Claim</a>
     */
    protected void populateSub(JWTClaimsSet.Builder builder, Authentication authentication) {
        builder.subject(authentication.getName()); // sub
    }

    /**
     * Populates aud claim.
     *
     * @param builder The Claims Builder
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.3">aud (Audience) Claim</a>
     */
    protected void populateAud(JWTClaimsSet.Builder builder) {
        if (claimsAudienceProvider != null) {
            builder.audience(claimsAudienceProvider.audience()); // aud
        }
    }

    /**
     * Populates exp claim.
     *
     * @param builder    The Claims Builder
     * @param expiration expiration time in seconds
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.4">exp (ExpirationTime) Claim</a>
     */
    protected void populateExp(JWTClaimsSet.Builder builder, @Nullable Integer expiration) {
        if (expiration != null) {
            LOG.debug("Setting expiration to {}", expiration);
            builder.expirationTime(Date.from(Instant.now().plus(expiration, ChronoUnit.SECONDS))); // exp
        }
    }

    /**
     * Populates nbf claim.
     *
     * @param builder The Claims Builder
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.5">nbf (Not Before) Claim</a>
     */
    protected void populateNbf(JWTClaimsSet.Builder builder) {
        builder.notBeforeTime(new Date()); // nbf
    }

    /**
     * Populates iat claim.
     *
     * @param builder The Claims Builder
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.6">iat (Issued At) Claim</a>
     */
    protected void populateIat(JWTClaimsSet.Builder builder) {
        builder.issueTime(new Date()); // iat
    }

    /**
     * Populates jti claim.
     *
     * @param builder The Claims Builder
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.7">jti (JWT ID) Claim</a>
     */
    protected void populateJti(JWTClaimsSet.Builder builder) {
        if (jwtIdGenerator != null) {
            builder.jwtID(jwtIdGenerator.generateJtiClaim()); // jti
        }
    }

    /**
     * Populates Claims with Authentication object.
     *
     * @param builder     the Claims Builder
     * @param authentication Authenticated user's representation.
     */
    protected void populateWithAuthentication(JWTClaimsSet.Builder builder, Authentication authentication) {
        populateSub(builder, authentication);
        authentication.getAttributes().forEach(builder::claim);
        String rolesKey = tokenConfiguration.getRolesName();
        if (!rolesKey.equalsIgnoreCase(TokenConfiguration.DEFAULT_ROLES_NAME)) {
            builder.claim(ROLES_KEY, rolesKey);
        }
        builder.claim(rolesKey, authentication.getRoles());
    }

    /**
     * @param oldClaims  The old claims to use as a base in the new token generation.
     * @param expiration expiration time in seconds
     * @return Instance of {@link JWTClaimsSet}
     */
    @Override
    public Map<String, Object> generateClaimsSet(Map<String, ?> oldClaims, Integer expiration) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        List<String> excludedClaims = Arrays.asList(JwtClaims.EXPIRATION_TIME, JwtClaims.ISSUED_AT, JwtClaims.NOT_BEFORE);
        for (String k : oldClaims.keySet()
                .stream()
                .filter(p -> !excludedClaims.contains(p))
                .collect(Collectors.toList())) {
            builder.claim(k, oldClaims.get(k));
        }
        populateExp(builder, expiration);
        populateIat(builder);
        populateNbf(builder);
        return builder.build().getClaims();
    }
}
