/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.endpoint.userinfo;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.naming.Named;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.Closeable;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * {@link TokenValidator} which uses a remote `UserInfo` endpoint to validate a token.
 * <p>
 * A token is only sent to the UserInfo endpoint when it can be attributed to exactly this provider: a JWT must carry an {@code iss}
 * claim equal to the provider issuer (see {@link IssuerUtils#equivalent(String, String)}) which no other provider expects. Tokens
 * which cannot be attributed (opaque tokens, JWTs without {@code iss}, JWTs of an issuer shared by several providers) are sent only
 * when {@link UserInfoClientTokenValidatorConfiguration#validateOpaqueTokens()} is {@code true}, or when it is unset and this is
 * the only OpenID client configured and the only UserInfo token validator in the application. This prevents access tokens issued by
 * one provider from being disclosed to the UserInfo endpoint of another provider.
 * </p>
 * <p>
 * The {@link Authentication} built from the UserInfo response is bound to the provider which answered. The attribute
 * {@link OauthAuthenticationMapper#PROVIDER_KEY} is always set to the provider name, overriding any value present in the
 * response, so a provider cannot claim that the user belongs to another provider. When more than one OAuth 2.0 client is
 * configured (or {@code micronaut.security.oauth2.openid.qualify-username-with-provider} is {@code true}), the username is qualified as {@code providerName:subject} so that a subject at one provider never
 * collides with the same subject at another provider. A qualified username is only unambiguous if the provider name does
 * not contain the separator, otherwise the provider {@code alpha} with the subject {@code beta:victim} and the provider
 * {@code alpha:beta} with the subject {@code victim} are the same user. Creating a validator which qualifies usernames
 * for a provider whose name contains {@value #PROVIDER_SEPARATOR} fails with a {@link ConfigurationException}.
 * </p>
 */
@Internal
final class UserInfoClientTokenValidator implements Closeable, TokenValidator<HttpRequest<?>>, Named {
    /**
     * Separator between the provider name and the subject in the username when several OAuth 2.0 clients are configured.
     */
    static final String PROVIDER_SEPARATOR = ":";
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientTokenValidator.class);
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private final HttpClient httpClient;
    private final String path;
    private final String name;
    @Nullable
    private final String issuer;
    @Nullable
    private final Boolean validateOpaqueTokens;
    private final Supplier<Boolean> issuerSharedWithAnotherProvider;
    private final Supplier<Boolean> soleUserInfoClientTokenValidator;
    private final boolean qualifyUsername;

    /**
     * @param name Provider name
     * @param httpClient HTTP client pointing to the authorization server
     * @param path UserInfo endpoint path
     * @param qualifyUsername Whether to qualify the username with the provider name. See {@link io.micronaut.security.oauth2.configuration.OpenIdConfiguration#getQualifyUsernameWithProvider()}.
     * @throws ConfigurationException if {@code qualifyUsername} is {@code true} and {@code name} contains {@value #PROVIDER_SEPARATOR}
     */
    UserInfoClientTokenValidator(String name, HttpClient httpClient, String path, boolean qualifyUsername) {
        this(name, httpClient, path, null, null, () -> false, () -> true, qualifyUsername);
    }

    /**
     * @param configuration UserInfo endpoint configuration: provider name, endpoint path, expected issuer and whether opaque tokens are validated
     * @param httpClient HTTP client pointing to the authorization server
     * @param issuerSharedWithAnotherProvider Whether another provider expects the same issuer. A JWT of a shared issuer cannot be attributed
     *                                        to exactly this provider and is handled like an opaque token.
     * @param soleUserInfoClientTokenValidator Whether this is the only UserInfo token validator in the application. Only consulted when
     *                                         {@link UserInfoClientTokenValidatorConfiguration#validateOpaqueTokens()} is unset.
     * @param qualifyUsername Whether to qualify the username with the provider name. See {@link io.micronaut.security.oauth2.configuration.OpenIdConfiguration#getQualifyUsernameWithProvider()}.
     * @throws ConfigurationException if {@code qualifyUsername} is {@code true} and the provider name contains {@value #PROVIDER_SEPARATOR}
     */
    UserInfoClientTokenValidator(UserInfoClientTokenValidatorConfiguration configuration,
                                 HttpClient httpClient,
                                 Supplier<Boolean> issuerSharedWithAnotherProvider,
                                 Supplier<Boolean> soleUserInfoClientTokenValidator,
                                 boolean qualifyUsername) {
        this(configuration.name(), httpClient, configuration.path(), configuration.issuer(), configuration.validateOpaqueTokens(), issuerSharedWithAnotherProvider, soleUserInfoClientTokenValidator, qualifyUsername);
    }

    private UserInfoClientTokenValidator(String name,
                                         HttpClient httpClient,
                                         String path,
                                         @Nullable String issuer,
                                         @Nullable Boolean validateOpaqueTokens,
                                         Supplier<Boolean> issuerSharedWithAnotherProvider,
                                         Supplier<Boolean> soleUserInfoClientTokenValidator,
                                         boolean qualifyUsername) {
        if (qualifyUsername && name.contains(PROVIDER_SEPARATOR)) {
            throw new ConfigurationException("OAuth 2.0 client name '" + name + "' must not contain '" + PROVIDER_SEPARATOR
                + "' because usernames of authentications validated via the UserInfo endpoint are qualified as <provider name>"
                + PROVIDER_SEPARATOR + "<sub>. Rename the client under micronaut.security.oauth2.clients or set micronaut.security.oauth2.openid.qualify-username-with-provider to false");
        }
        this.name = name;
        this.httpClient = httpClient;
        this.path = path;
        this.issuer = issuer;
        this.validateOpaqueTokens = validateOpaqueTokens;
        this.issuerSharedWithAnotherProvider = issuerSharedWithAnotherProvider;
        this.soleUserInfoClientTokenValidator = soleUserInfoClientTokenValidator;
        this.qualifyUsername = qualifyUsername;
    }

    @Override
    public @NonNull String getName() {
        return name;
    }

    /**
     * @return The issuer expected in the {@code iss} claim of the tokens sent to this UserInfo endpoint, or {@code null} if unknown.
     */
    @Nullable
    String issuer() {
        return issuer;
    }

    @Override
    public void close() {
        httpClient.close();
    }

    @Override
    @NonNull
    public Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
        if (!shouldValidate(token)) {
            return Mono.empty();
        }
        return Mono.from(httpClient.retrieve(HttpRequest.GET(path).bearerAuth(token),
                MAP_ARGUMENT))
            .flatMap(m -> {
                Authentication authentication = createAuthentication(m);
                return authentication == null ? Mono.empty() : Mono.just(authentication);
            })
            .onErrorResume(t -> {
                if (t instanceof HttpClientResponseException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Token not validated. UserInfo endpoint for client {} responded with HTTP status code {} while validating the token", getName(), ex.getStatus().getCode());
                    }
                }
                if (LOG.isTraceEnabled()) {
                    LOG.trace(t.getMessage(), t);
                }
                return Mono.empty();
            });
    }

    /**
     * The token is parsed at most once per invocation, by {@link #issuerClaim(String)}.
     *
     * @param token The token
     * @return Whether the token can be attributed to this provider and thus may be sent to its UserInfo endpoint.
     */
    private boolean shouldValidate(@NonNull String token) {
        String tokenIssuer = issuerClaim(token);
        if (tokenIssuer == null) {
            return shouldValidateUnattributableToken();
        }
        if (issuer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Issuer of UserInfo endpoint for client {} is unknown. Treating the JWT as an opaque token", getName());
            }
            return shouldValidateUnattributableToken();
        }
        if (!IssuerUtils.equivalent(issuer, tokenIssuer)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token not sent to the UserInfo endpoint for client {}. Its iss claim does not match the client issuer", getName());
            }
            return false;
        }
        if (issuerSharedWithAnotherProvider.get()) {
            // Several providers expect this issuer (for example several tenants of one provider) but have distinct UserInfo
            // endpoints. Which one issued the token is unknown, so sending it to this provider needs an explicit opt-in.
            // The implicit sole-provider allowance never applies: a shared issuer proves that another provider exists.
            boolean optedIn = Boolean.TRUE.equals(validateOpaqueTokens);
            if (!optedIn && LOG.isDebugEnabled()) {
                LOG.debug("Token not sent to the UserInfo endpoint for client {}. Its issuer is shared with another client and validation of opaque tokens is not enabled for it", getName());
            }
            return optedIn;
        }
        return true;
    }

    /**
     * @return Whether a token which cannot be attributed to exactly this provider (an opaque token, a JWT without {@code iss}, or a JWT
     * of an issuer shared with another provider) may be sent to its UserInfo endpoint.
     */
    private boolean shouldValidateUnattributableToken() {
        boolean validate = validateOpaqueTokens != null ? validateOpaqueTokens : soleUserInfoClientTokenValidator.get();
        if (!validate && LOG.isDebugEnabled()) {
            LOG.debug("Token not sent to the UserInfo endpoint for client {}. It cannot be attributed to this provider and validation of opaque tokens is not enabled for it", getName());
        }
        return validate;
    }

    /**
     * Reads the {@code iss} claim of an untrusted token without verifying it. The signature is irrelevant here: the claim only
     * decides which provider, if any, the token is sent to, and the provider verifies the token itself.
     *
     * @param token The token
     * @return The {@code iss} claim of the token if it is a JWT with a non-empty issuer. {@code null} for opaque tokens, encrypted JWTs or JWTs without an issuer.
     */
    @Nullable
    private static String issuerClaim(@NonNull String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            if (claimsSet == null) {
                return null;
            }
            String iss = claimsSet.getIssuer();
            return StringUtils.isEmpty(iss) ? null : iss;
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Builds an {@link Authentication} bound to this provider from the claims returned by its UserInfo endpoint.
     * @param claims Claims returned by the UserInfo endpoint
     * @return {@code null} if the response has no {@code sub} claim. Otherwise, an authentication whose {@link OauthAuthenticationMapper#PROVIDER_KEY} attribute is this provider's name.
     */
    @Nullable
    private Authentication createAuthentication(@NonNull Map<String, Object> claims) {
        Object subject = claims.get(Claims.SUBJECT);
        if (subject == null) {
            return null;
        }
        Map<String, Object> attributes = new HashMap<>(claims);
        Object claimedProvider = attributes.put(OauthAuthenticationMapper.PROVIDER_KEY, name);
        if (claimedProvider != null && !name.equals(claimedProvider) && LOG.isWarnEnabled()) {
            LOG.warn("UserInfo response of client {} claimed to belong to provider {}. Ignoring it", getName(), claimedProvider);
        }
        String username = qualifyUsername ? name + PROVIDER_SEPARATOR + subject : subject.toString();
        return Authentication.build(username, attributes);
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE - 100;
    }
}
