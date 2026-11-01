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
package io.micronaut.security.oauth2;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.naming.Named;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link ProviderResolver}.
 *
 * <p>The provider is read from the {@link OauthAuthenticationMapper#PROVIDER_KEY} attribute when present. The attribute is set
 * by this application during the authorization code flow; an ID token carrying a
 * claim with that name is rejected by {@link io.micronaut.security.oauth2.client.IdTokenClaimsValidator}, so with
 * {@code micronaut.security.authentication=idtoken} the attribute never comes from the token which authenticated the request.</p>
 *
 * <p>Otherwise the provider is inferred from the token claims: the OpenID clients whose configured issuer matches the {@code iss}
 * claim are the candidates. If several clients match the issuer (for example two Oracle Cloud identity domains, whose ID tokens
 * share the same {@code iss} claim) the {@code aud} claim, and if needed the {@code azp} claim, are compared with the clients'
 * {@code client-id} to pick the client the token was issued to. If exactly one client cannot be determined, no provider is
 * resolved. OpenID clients whose OAuth 2.0 client is disabled are ignored.</p>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultProviderResolver implements ProviderResolver {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultProviderResolver.class);
    private static final String AUTHORIZED_PARTY = "azp";

    private final List<OpenIdClientConfiguration> openIdClientConfigurations;
    private final Collection<OauthClientConfiguration> oauthClientConfigurations;

    /**
     * @param openIdClientConfigurations OpenID client configurations
     * @param oauthClientConfigurations OAuth 2.0 client configurations. OpenID clients whose OAuth 2.0 client is disabled are ignored.
     * @since 3.11.3
     */
    @Inject
    public DefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations,
                                   Collection<OauthClientConfiguration> oauthClientConfigurations) {
        this.oauthClientConfigurations = oauthClientConfigurations.stream()
            .filter(OauthClientConfiguration::isEnabled)
            .collect(Collectors.toList());
        Set<String> disabled = oauthClientConfigurations.stream()
            .filter(conf -> !conf.isEnabled())
            .map(OauthClientConfiguration::getName)
            .collect(Collectors.toSet());
        this.openIdClientConfigurations = openIdClientConfigurations.stream()
            .filter(conf -> !disabled.contains(conf.getName()))
            .collect(Collectors.toList());
    }

    /**
     * @param openIdClientConfigurations OpenID client configurations
     * @deprecated Use {@link #DefaultProviderResolver(List, Collection)} instead, which ignores disabled OAuth 2.0 clients. Without
     * the OAuth 2.0 client configurations the {@code aud} claim cannot be used to tell apart OpenID clients whose issuers overlap,
     * and no provider is resolved in that case.
     */
    @Deprecated
    public DefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
        this.openIdClientConfigurations = openIdClientConfigurations;
        this.oauthClientConfigurations = Collections.emptyList();
    }

    @Override
    public Optional<String> resolveProvider(Authentication authentication) {
        Object providerKey = authentication.getAttributes().get(OauthAuthenticationMapper.PROVIDER_KEY);
        if (providerKey != null) {
            return Optional.of(providerKey.toString());
        }
        return openIdClientNameWhichMatchesIssClaim(authentication);
    }

    /**
     * Resolves the provider from the {@code iss} claim. {@link #openIdClientNameWhichMatchesIssuer(String)} decides whether the
     * issuer maps to a client: if it returns no client, no provider is resolved. If it returns one of several clients which match
     * the issuer, {@link #openIdClientNameWhichMatchesAudience(Authentication, List)} picks among them the client the token was
     * issued to.
     *
     * @param authentication State of authentication
     * @return {@literal Optional#empty()} if iss claim not found, if the iss claim does not match the issuer of any open id client, or if the iss claim matches several open id clients and the aud and azp claims do not single out one of them. If exactly one open id client matches, its name is returned wrapped in an optional
     */
    protected Optional<String> openIdClientNameWhichMatchesIssClaim(Authentication authentication) {
        Object issuer = authentication.getAttributes().get(JwtClaims.ISSUER);
        if (issuer == null) {
            return Optional.empty();
        }
        String iss = issuer.toString();
        Optional<String> name = openIdClientNameWhichMatchesIssuer(iss);
        if (!name.isPresent()) {
            return Optional.empty();
        }
        List<String> candidates = openIdClientNamesWhichMatchIssuer(iss);
        if (candidates.size() < 2 || !candidates.contains(name.get())) {
            return name;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("iss claim [{}] matches the issuer of several OpenID clients {}. Using the aud claim to resolve the provider", iss, candidates);
        }
        return openIdClientNameWhichMatchesAudience(authentication, candidates);
    }

    /**
     * The issuer matches an open id client when it is identical to the expected issuer of the client; only the case of the
     * scheme and a single trailing slash are tolerated. See {@link IssuerUtils#equivalent(String, String)}. When several clients
     * match the issuer, the first one is returned and {@link #openIdClientNameWhichMatchesIssClaim(Authentication)} uses the
     * {@code aud} claim to pick among them.
     *
     * <p>Subclasses may override this method to customize how the issuer is mapped to a client. If it returns no client, no
     * provider is resolved. A client which is not one of the clients matching the issuer is used as is.</p>
     *
     * @param issuer Token Issuer
     * @return {@literal Optional#empty()} if the issuer does not match the expected issuer ({@link OpenIdClientConfiguration#getIssuerIdentifier()}) of any open id client. If it matches, the open id client is returned wrapped in an optional
     */
    @NonNull
    protected Optional<String> openIdClientNameWhichMatchesIssuer(@NonNull String issuer) {
        return openIdClientNamesWhichMatchIssuer(issuer).stream().findFirst();
    }

    /**
     *
     * @param issuer Token Issuer
     * @return The names of every open id client whose expected issuer ({@link OpenIdClientConfiguration#getIssuerIdentifier()}) matches the token issuer
     * @since 3.11.3
     */
    @NonNull
    protected List<String> openIdClientNamesWhichMatchIssuer(@NonNull String issuer) {
        return openIdClientConfigurations.stream()
                .filter(conf -> conf.getIssuerIdentifier()
                        .map(expectedIssuer -> IssuerUtils.equivalent(expectedIssuer, issuer))
                        .orElse(false))
                .map(Named::getName)
                .collect(Collectors.toList());
    }

    /**
     * Picks, among the open id clients whose issuer matches the token, the one whose {@code client-id} the token was issued to.
     * The {@code aud} claim must contain the client id. If the {@code aud} claim contains the client id of several candidates, the
     * {@code azp} claim must be equal to the client id of exactly one of them.
     *
     * @param authentication State of authentication
     * @param candidateNames Names of the open id clients whose issuer matches the token issuer
     * @return The name of the only candidate the token was issued to, or {@literal Optional#empty()} if the token audience does not single out one candidate
     * @since 3.11.3
     */
    @NonNull
    protected Optional<String> openIdClientNameWhichMatchesAudience(@NonNull Authentication authentication,
                                                                    @NonNull List<String> candidateNames) {
        List<String> audiences = parseAudiences(authentication);
        if (audiences.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("aud claim not present. Cannot resolve the provider among the OpenID clients {}", candidateNames);
            }
            return Optional.empty();
        }
        List<OauthClientConfiguration> matches = new ArrayList<>();
        for (OauthClientConfiguration conf : oauthClientConfigurations) {
            if (candidateNames.contains(conf.getName()) && audiences.contains(conf.getClientId())) {
                matches.add(conf);
            }
        }
        if (matches.size() > 1) {
            String azp = parseAuthorizedParty(authentication);
            if (azp != null) {
                matches.removeIf(conf -> !azp.equals(conf.getClientId()));
            }
        }
        if (matches.size() != 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("aud and azp claims match {} of the OpenID clients {}. Cannot resolve the provider", matches.size(), candidateNames);
            }
            return Optional.empty();
        }
        return Optional.of(matches.get(0).getName());
    }

    @NonNull
    private static List<String> parseAudiences(@NonNull Authentication authentication) {
        Object aud = authentication.getAttributes().get(JwtClaims.AUDIENCE);
        if (aud == null) {
            return Collections.emptyList();
        }
        List<String> audiences = new ArrayList<>();
        if (aud instanceof Collection) {
            for (Object audience : (Collection<?>) aud) {
                if (audience != null) {
                    audiences.add(audience.toString());
                }
            }
        } else if (aud instanceof Object[]) {
            for (Object audience : (Object[]) aud) {
                if (audience != null) {
                    audiences.add(audience.toString());
                }
            }
        } else {
            audiences.add(aud.toString());
        }
        return audiences;
    }

    @Nullable
    private static String parseAuthorizedParty(@NonNull Authentication authentication) {
        Object azp = authentication.getAttributes().get(AUTHORIZED_PARTY);
        return azp == null ? null : azp.toString();
    }
}
