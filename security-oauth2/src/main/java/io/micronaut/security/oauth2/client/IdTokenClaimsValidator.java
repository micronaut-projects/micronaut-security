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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidatorConfigurationProperties;
import jakarta.inject.Singleton;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * For {@link io.micronaut.security.authentication.AuthenticationMode#IDTOKEN} authentication mode performs the following verification as described in the OpenID Connect Spec.
 *
 * - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
 * - The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element.
 * - If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
 * - If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
 *  * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation</a>
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Requires(property = JwtClaimsValidatorConfigurationProperties.PREFIX + ".openid-idtoken", notEquals = StringUtils.FALSE)
@Singleton
public class IdTokenClaimsValidator implements GenericJwtClaimsValidator {
    protected static final Logger LOG = LoggerFactory.getLogger(IdTokenClaimsValidator.class);
    protected static final String AUTHORIZED_PARTY = "azp";

    protected final Collection<OauthClientConfiguration> oauthClientConfigurations;

    /**
     *
     * @param oauthClientConfigurations OpenId client configurations
     */
    public IdTokenClaimsValidator(Collection<OauthClientConfiguration> oauthClientConfigurations) {
        this.oauthClientConfigurations = oauthClientConfigurations;
    }

    @Override
    public boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
        Optional<String> claimIssuerOptional = parseIssuerClaim(claims);
        if (!claimIssuerOptional.isPresent()) {
            return false;
        }
        String iss = claimIssuerOptional.get();

        Optional<List<String>> audiencesOptional = parseAudiences(claims);
        if (!audiencesOptional.isPresent()) {
            return false;
        }
        List<String> audiences = audiencesOptional.get();
        return validateIssuerAudienceAndAzp(claims, iss, audiences);
    }

    /**
     *
     * @param claims JWT Claims
     * @return the iss claim value wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<String> parseIssuerClaim(JwtClaims claims) {
        return parseClaimString(claims, JwtClaims.ISSUER);
    }

    /**
     *
     * @param claims JWT Claims
     * @param claimName Claim Name
     * @return the claim value wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<Object> parseClaim(JwtClaims claims, String claimName) {
        Object obj = claims.get(claimName);
        if (obj == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim not present", claimName);
            }
            return Optional.empty();
        }
        return Optional.of(obj);
    }

    /**
     *
     * @param claims JWT Claims
     * @param claimName Claim Name
     * @return the claim value as a String wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<String> parseClaimString(JwtClaims claims, String claimName) {
        return parseClaim(claims, claimName).map(Object::toString);
    }

    /**
     *
     * @param claims JWT Claims
     * @param claimName Claim Name
     * @return the claim value as a list of Strings wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<List<String>> parseClaimList(JwtClaims claims, String claimName) {
        Optional<Object> objectOptional = parseClaim(claims, claimName);
        if (!objectOptional.isPresent()) {
            return Optional.empty();
        }
        Object obj = objectOptional.get();
        List<String> result = new ArrayList<>();
        if (obj instanceof List) {
            for (Object listObj : (List<?>) obj) {
                result.add(listObj.toString());
            }
        } else {
            result.add(obj.toString());
        }
        return Optional.of(result);
    }

    /**
     *
     * @param claims JWT Claims
     * @return the aud claim value a list of strings wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<List<String>> parseAudiences(JwtClaims claims) {
        return parseClaimList(claims, JwtClaims.AUDIENCE);
    }

    /**
     *
     * @param claims JWT Claims
     * @param iss Issuer claim
     * @param audiences aud claim as a list of string
     * @return true if an OAuth 2.0 client issuer matches the iss claim, any of the audiences in the aud claim matches the OAuth 2.0 client_id and for multiple audiencies the azp claim is present and matches OAuth 2.0 client_id
     */
    protected boolean validateIssuerAudienceAndAzp(@NonNull JwtClaims claims,
                                                   @NonNull String iss,
                                                   @NonNull List<String> audiences) {
        return oauthClientConfigurations.stream().anyMatch(oauthClientConfiguration -> validateIssuerAudienceAndAzp(claims, iss, audiences, oauthClientConfiguration));
    }

    /**
     *
     * @param claims JWT Claims
     * @param iss Issuer claim
     * @param audiences aud claim as a list of string
     * @param oauthClientConfiguration OAuth 2.0 client configuration
     * @return true if the OAuth 2.0 client OpenID issuer matches the iss claim, any of the audiences in the aud claim matches the OAuth 2.0 client_id and for multiple audiencies the azp claim is present and matches OAuth 2.0 client_id
     */
    protected boolean validateIssuerAudienceAndAzp(@NonNull JwtClaims claims,
                                                   @NonNull String iss,
                                                   @NonNull List<String> audiences,
                                                   @NonNull OauthClientConfiguration oauthClientConfiguration) {
        Optional<OpenIdClientConfiguration> openIdClientConfigurationOptional = oauthClientConfiguration.getOpenid();
        if (openIdClientConfigurationOptional.isPresent()) {
            OpenIdClientConfiguration openIdClientConfiguration = openIdClientConfigurationOptional.get();
            return validateIssuerAudienceAndAzp(claims, iss, audiences, oauthClientConfiguration.getClientId(), openIdClientConfiguration);
        }
        return false;
    }

    /**
     *
     * @param claims JWT Claims
     * @param iss Issuer claim
     * @param audiences aud claim as a list of string
     * @param clientId OAuth 2.0 client_id
     * @param openIdClientConfiguration OpenID OAuth 2.0 client configuration
     * @return true if the OAuth 2.0 client OpenID issuer matches the iss claim, any of the audiences in the aud claim matches the OAuth 2.0 client_id and for multiple audiencies the azp claim is present and matches OAuth 2.0 client_id
     */
    protected boolean validateIssuerAudienceAndAzp(@NonNull JwtClaims claims,
                                                   @NonNull String iss,
                                                   @NonNull List<String> audiences,
                                                   @NonNull String clientId,
                                                   @NonNull OpenIdClientConfiguration openIdClientConfiguration) {
        if (openIdClientConfiguration.getIssuer().isPresent()) {
            Optional<URL> issuerOptional = openIdClientConfiguration.getIssuer();
            if (issuerOptional.isPresent()) {
                String issuer = issuerOptional.get().toString();
                return issuer.equalsIgnoreCase(iss) ||
                        audiences.contains(clientId) &&
                                validateAzp(claims, clientId, audiences);
            }
        }
        return false;
    }

    /**
     *
     * @param claims JWT Claims
     * @return the azp claim value wrapped in an {@link Optional}. If not found, an empty {@link Optional} is returned.
     */
    protected Optional<String> parseAzpClaim(JwtClaims claims) {
        return parseClaimString(claims, AUTHORIZED_PARTY);
    }

    /**
     *
     * @param claims JWT Claims
     * @param clientId OAuth 2.0 client ID
     * @param audiences audiences specified in the JWT Claims
     * @return true for single audiences, for multiple audiences returns true azp claim is present and matches OAuth 2.0 client_id
     */
    protected boolean validateAzp(@NonNull JwtClaims claims,
                                  @NonNull String clientId,
                                  @NonNull List<String> audiences) {
        if (audiences.size() < 2) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} claim is not required for single audiences", AUTHORIZED_PARTY);
            }
            return true;
        }
       Optional<String> azpOptional = parseAzpClaim(claims);
        if (!azpOptional.isPresent()) {
            return false;
        }
        String azp = azpOptional.get();
        boolean result = azp.equalsIgnoreCase(clientId);
        if (!result && LOG.isTraceEnabled()) {
            LOG.trace("{} claim does not match client id {}", AUTHORIZED_PARTY, clientId);
        }
        return result;
    }
}
