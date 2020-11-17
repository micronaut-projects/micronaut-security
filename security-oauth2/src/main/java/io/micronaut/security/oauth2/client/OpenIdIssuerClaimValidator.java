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
package io.micronaut.security.oauth2.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Singleton;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import javax.inject.Singleton;

/**
 * Validates that the JWT {@code iss} claim matches any of the OAuth 2.0 OpenID client issuer exposed via  {@code .well-known/openid-configuration}.
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Requires(property = JwtClaimsValidator.PREFIX + ".openid-issuer", notEquals = StringUtils.FALSE)
@Singleton
public class OpenIdIssuerClaimValidator implements GenericJwtClaimsValidator {

    private final List<String> openIdClientIssuers;

    /**
     *
     * @param openIdClientConfigurations OpenId client configurations
     */
    public OpenIdIssuerClaimValidator(Collection<OpenIdClientConfiguration> openIdClientConfigurations) {
        this.openIdClientIssuers = openIdClientIssuers(openIdClientConfigurations);
    }

    /**
     *
     * @param openIdClientConfigurations OpenId client configurations
     * @return a list of issuers urls
     */
    @NonNull
    protected List<String> openIdClientIssuers(@NonNull Collection<OpenIdClientConfiguration> openIdClientConfigurations) {
        return openIdClientConfigurations.stream()
                .filter(openIdClientConfiguration -> openIdClientConfiguration.getIssuer().isPresent())
                .map(openIdClientConfiguration -> openIdClientConfiguration.getIssuer().get().toString())
                .collect(Collectors.toList());
    }

    @Override
    public boolean validate(JwtClaims claims) {
        return validate(claims, null);
    }

    @Override
    public boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
        if (claims.contains(JwtClaims.ISSUER)) {
            Object obj = claims.get(JwtClaims.ISSUER);
            if (obj == null) {
                return false;
            }
            String issuer = obj.toString();
            return openIdClientIssuers
                    .stream()
                    .anyMatch(iss -> iss.equalsIgnoreCase(issuer));
        }
        return false;
    }
}
