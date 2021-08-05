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
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

import jakarta.inject.Singleton;
import java.util.List;
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

    public DefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
        this. openIdClientConfigurations =  openIdClientConfigurations;
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
        Object issuer = authentication.getAttributes().get(JwtClaims.ISSUER);
        return issuer != null ? openIdClientNameWhichMatchesIssuer(issuer.toString()) : Optional.empty();
    }

    /**
     *
     * @param issuer Token Issuer
     * @return {@literal Optional#empty()} if the issuer does not match the issuer of any open id client. If it matches, the open id client is returned wrapped in an optional
     */
    @NonNull
    protected Optional<String> openIdClientNameWhichMatchesIssuer(@NonNull String issuer) {
        for (OpenIdClientConfiguration conf : openIdClientConfigurations) {
            if (conf.getIssuer().isPresent()) {
                // use starts with instead of equals because you may have in config a trailing slash
                if (conf.getIssuer().get().toString().startsWith(issuer)) {
                    return Optional.of(conf.getName());
                }
            }
        }
        return Optional.empty();
    }
}
