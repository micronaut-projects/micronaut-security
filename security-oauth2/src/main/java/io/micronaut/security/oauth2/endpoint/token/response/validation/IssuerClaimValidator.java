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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.client.OpenIdIssuers;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
 * <p>
 * The {@code iss} claim must exactly match the issuer of the provider metadata. In addition, when the OpenID client
 * configures an issuer ({@code micronaut.security.oauth2.clients.*.openid.issuer} or {@code issuer-identifier}), the {@code iss} claim must also match
 * that configured issuer. The issuer of the provider metadata is asserted by the provider itself, so it must never widen
 * the set of issuers a client accepts: a provider announcing another provider's issuer in its discovery document cannot
 * get ID tokens of that issuer accepted on its own callback.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">Open ID Provider Metadata Spec</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation - OpenID Connect Core Spec</a>.
 * @since 1.2.0
 * @author Sergio del Amo
 */
@Requires(property = OauthConfigurationProperties.OpenIdConfigurationProperties.ClaimsValidationConfigurationProperties.PREFIX + ".issuer", notEquals = StringUtils.FALSE)
@Singleton
public class IssuerClaimValidator implements OpenIdClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(IssuerClaimValidator.class);

    @Override
    public boolean validate(OpenIdClaims claims,
                            OauthClientConfiguration clientConfiguration,
                            OpenIdProviderMetadata providerMetadata) {
        String issuer = claims.getIssuer();
        if (issuer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("issuer claim does not exist");
            }
            return false;
        }
        Optional<String> configuredIssuer = configuredIssuer(clientConfiguration);
        if (configuredIssuer.isPresent() && !OpenIdIssuers.equivalent(configuredIssuer.get(), issuer)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT issuer claim [{}] does not match the configured issuer [{}] of OpenID client [{}]", issuer, configuredIssuer.get(), clientConfiguration.getName());
            }
            return false;
        }
        //The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
        boolean condition = issuer.equals(providerMetadata.getIssuer());
        if (!condition && LOG.isDebugEnabled()) {
            LOG.debug("JWT issuer claim does not match {}", providerMetadata.getIssuer());
        }
        return condition;
    }

    /**
     * @param clientConfiguration OAuth 2.0 client configuration
     * @return The issuer configured for the OpenID client, if any
     * @since 5.5.2
     */
    @NonNull
    protected Optional<String> configuredIssuer(@NonNull OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
            .flatMap(OpenIdClientConfiguration::getIssuerIdentifier);
    }
}
