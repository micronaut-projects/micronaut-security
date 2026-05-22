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

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Secondary;
import io.micronaut.context.env.Environment;
import io.micronaut.core.util.StringUtils;
import io.micronaut.runtime.ApplicationConfiguration;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.claims.ClaimsAudienceProvider;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.claims.JtiGenerator;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Default claims generator used when no other {@link ClaimsGenerator} is available.
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".secret")
@Secondary
@Singleton
class DefaultMacaroonClaimsGenerator implements ClaimsGenerator {

    private static final String ROLES_KEY = "rolesKey";

    private final TokenConfiguration tokenConfiguration;
    private final JtiGenerator jtiGenerator;
    private final ClaimsAudienceProvider claimsAudienceProvider;
    private final String appName;

    DefaultMacaroonClaimsGenerator(TokenConfiguration tokenConfiguration,
                                   @Nullable JtiGenerator jtiGenerator,
                                   @Nullable ClaimsAudienceProvider claimsAudienceProvider,
                                   @Nullable ApplicationConfiguration applicationConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
        this.jtiGenerator = jtiGenerator;
        this.claimsAudienceProvider = claimsAudienceProvider;
        this.appName = applicationConfiguration != null ? applicationConfiguration.getName().orElse(Environment.MICRONAUT) : Environment.MICRONAUT;
    }

    @Override
    public Map<String, Object> generateClaims(Authentication authentication, @Nullable Integer expiration) {
        Map<String, Object> claims = new LinkedHashMap<>();
        populateIat(claims);
        populateExp(claims, expiration);
        populateJti(claims);
        populateIss(claims);
        populateAud(claims);
        populateNbf(claims);
        populateWithAuthentication(claims, authentication);
        return claims;
    }

    @Override
    public Map<String, Object> generateClaimsSet(Map<String, ?> oldClaims, Integer expiration) {
        Map<String, Object> claims = new LinkedHashMap<>();
        List<String> excludedClaims = Arrays.asList(Claims.EXPIRATION_TIME, Claims.ISSUED_AT, Claims.NOT_BEFORE);
        oldClaims.forEach((key, value) -> {
            if (!excludedClaims.contains(key)) {
                claims.put(key, value);
            }
        });
        populateExp(claims, expiration);
        populateIat(claims);
        populateNbf(claims);
        return claims;
    }

    private void populateIss(Map<String, Object> claims) {
        claims.put(Claims.ISSUER, appName);
    }

    private void populateAud(Map<String, Object> claims) {
        if (claimsAudienceProvider != null) {
            claims.put(Claims.AUDIENCE, claimsAudienceProvider.audience());
        }
    }

    private void populateExp(Map<String, Object> claims, @Nullable Integer expiration) {
        if (expiration != null) {
            claims.put(Claims.EXPIRATION_TIME, Date.from(Instant.now().plus(expiration, ChronoUnit.SECONDS)));
        }
    }

    private void populateNbf(Map<String, Object> claims) {
        claims.put(Claims.NOT_BEFORE, new Date());
    }

    private void populateIat(Map<String, Object> claims) {
        claims.put(Claims.ISSUED_AT, new Date());
    }

    private void populateJti(Map<String, Object> claims) {
        if (jtiGenerator != null) {
            claims.put(Claims.TOKEN_ID, jtiGenerator.generateJtiClaim());
        }
    }

    private void populateWithAuthentication(Map<String, Object> claims, Authentication authentication) {
        claims.put(Claims.SUBJECT, authentication.getName());
        claims.putAll(authentication.getAttributes());
        String rolesKey = tokenConfiguration.getRolesName();
        if (!rolesKey.equalsIgnoreCase(TokenConfiguration.DEFAULT_ROLES_NAME)) {
            claims.put(ROLES_KEY, rolesKey);
        }
        claims.put(rolesKey, authentication.getRoles());
    }
}
