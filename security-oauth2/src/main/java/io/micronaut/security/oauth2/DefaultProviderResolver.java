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
package io.micronaut.security.oauth2;

import org.jspecify.annotations.NonNull;
import io.micronaut.core.naming.Named;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Optional;

/**
 * Default implementation of {@link ProviderResolver}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultProviderResolver implements ProviderResolver {
    private final List<OpenIdClientConfiguration> openIdClientConfigurations;

    /**
     * @param openIdClientConfigurations OpenID client configurations
     * @param oauthClientConfigurations OAuth 2.0 client configurations. OpenID clients whose OAuth 2.0 client is disabled are ignored.
     */
    @Inject
    public DefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations,
                                   Collection<OauthClientConfiguration> oauthClientConfigurations) {
        Set<String> disabled = oauthClientConfigurations.stream()
            .filter(conf -> !conf.isEnabled())
            .map(OauthClientConfiguration::getName)
            .collect(Collectors.toSet());
        this.openIdClientConfigurations = openIdClientConfigurations.stream()
            .filter(conf -> !disabled.contains(conf.getName()))
            .toList();
    }

    /**
     * @param openIdClientConfigurations OpenID client configurations
     * @deprecated Use {@link #DefaultProviderResolver(List, Collection)} instead, which ignores disabled OAuth 2.0 clients.
     */
    @Deprecated(since = "5.5.2")
    public DefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
        this.openIdClientConfigurations = openIdClientConfigurations;
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
     *
     * @param authentication State of authentication
     * @return {@literal Optional#empty()} if iss claim not found, or if the iss claim does not match the issuer of any open id client. If it matches, the open id client is returned wrapped in an optional
     */
    protected Optional<String> openIdClientNameWhichMatchesIssClaim(Authentication authentication) {
        Object issuer = authentication.getAttributes().get(Claims.ISSUER);
        return issuer != null ? openIdClientNameWhichMatchesIssuer(issuer.toString()) : Optional.empty();
    }

    /**
     * The issuer matches an open id client when it is identical to the expected issuer of the client; only the case of the
     * scheme and a single trailing slash are tolerated. See {@link IssuerUtils#equivalent(String, String)}.
     * @param issuer Token Issuer
     * @return {@literal Optional#empty()} if the issuer does not match the expected issuer ({@link OpenIdClientConfiguration#getIssuerIdentifier()}) of any open id client. If it matches, the open id client is returned wrapped in an optional
     */
    @NonNull
    protected Optional<String> openIdClientNameWhichMatchesIssuer(@NonNull String issuer) {
        return openIdClientConfigurations.stream()
                .filter(conf -> conf.getIssuerIdentifier()
                        .map(expectedIssuer -> IssuerUtils.equivalent(expectedIssuer, issuer))
                        .orElse(false))
                .map(Named::getName)
                .findFirst();
    }
}
