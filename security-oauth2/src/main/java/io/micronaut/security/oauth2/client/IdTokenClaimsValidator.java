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
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * For {@value io.micronaut.security.authentication.AuthenticationMode#IDTOKEN} authentication mode  performs the following verification as described in the OpenID Connect Spec.
 *
 * - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
 * - The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element.
 * - If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
 * - If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
 *  * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation</a>
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Requires(property = JwtClaimsValidator.PREFIX + ".openid-idtoken", notEquals = StringUtils.FALSE)
@Singleton
public class IdTokenClaimsValidator implements GenericJwtClaimsValidator {
    private static final Logger LOG = LoggerFactory.getLogger(IdTokenClaimsValidator.class);
    private static final String AUTHORIZED_PARTY = "azp";

    private final Collection<OauthClientConfiguration> oauthClientConfigurations;

    /**
     *
     * @param oauthClientConfigurations OpenId client configurations
     */
    public IdTokenClaimsValidator(Collection<OauthClientConfiguration> oauthClientConfigurations) {
        this.oauthClientConfigurations = oauthClientConfigurations;
    }

    @Override
    public boolean validate(JwtClaims claims) {
        return validate(claims, null);
    }

    @Override
    public boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
        Object obj = claims.get(JwtClaims.ISSUER);
        if (obj == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim not present", JwtClaims.ISSUER);
            }
            return false;
        }
        String iss = obj.toString();
        obj = claims.get(JwtClaims.AUDIENCE);
        if (obj == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim not present", JwtClaims.AUDIENCE);
            }
            return false;
        }
        List<String> audiences = new ArrayList<>();
        if (obj instanceof List) {
            for (Object listObj : (List<?>) obj) {
                audiences.add(listObj.toString());
            }
        } else {
            audiences.add(obj.toString());
        }
        for (OauthClientConfiguration oauthClientConfiguration : oauthClientConfigurations) {
            Optional<OpenIdClientConfiguration> openIdClientConfigurationOptional = oauthClientConfiguration.getOpenid();
            if (openIdClientConfigurationOptional.isPresent()) {
                OpenIdClientConfiguration openIdClientConfiguration = openIdClientConfigurationOptional.get();
                if (openIdClientConfiguration.getIssuer().isPresent()) {
                    Optional<URL> issuerOptional = openIdClientConfiguration.getIssuer();
                    if (issuerOptional.isPresent()) {
                        String issuer = issuerOptional.get().toString();
                        String clientId = oauthClientConfiguration.getClientId();
                        if (issuer.equalsIgnoreCase(iss) ||
                                audiences.contains(clientId) &&
                                        validateAzp(clientId, claims, audiences)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean validateAzp(@NonNull String clientId,
                                @NonNull JwtClaims claims,
                                @NonNull List<String> audiences) {
        if (audiences.size() < 2) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim is not required for single audiences", AUTHORIZED_PARTY);
            }
            return true;
        }
        Object obj = claims.get(AUTHORIZED_PARTY);
        if (obj == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim not present", AUTHORIZED_PARTY);
            }
            return false;
        }
        String azp = obj.toString();
        boolean result = azp.equalsIgnoreCase(clientId);
        if (!result) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim does not match client id {}", AUTHORIZED_PARTY, clientId);
            }
        }
        return result;
    }
}
