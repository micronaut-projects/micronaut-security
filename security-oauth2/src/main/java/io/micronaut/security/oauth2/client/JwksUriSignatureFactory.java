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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

/**
 * Factory to create {@link ReactiveJwksSignature} beans for the {@link OpenIdProviderMetadata#getJwksUri()} of OpenID clients.
 * <p>
 * The beans are only created for the {@link io.micronaut.security.authentication.AuthenticationMode#IDTOKEN} authentication mode, where the
 * ID token issued by the provider is the request credential. In any other authentication mode, tokens signed by the provider's keys, such
 * as ID tokens issued to other clients, must not authenticate requests. The ID token obtained during the authorization code flow is
 * validated against the provider's JWKS independently of these beans.
 * <p>
 * The key set of a provider is bound to the issuer of that provider (see {@link JwksSignatureConfiguration#getIssuer()}),
 * so that a token whose {@code iss} claim names one provider cannot be verified with the keys of another provider.
 *
 * @author Sergio del Amo
 * @since 1.3.0
 */
@Factory
@Internal
public class JwksUriSignatureFactory {
    private static final Logger LOG = LoggerFactory.getLogger(JwksUriSignatureFactory.class);

    /**
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @return a {@link JwksSignatureConfiguration} pointed to the jwks_uri exposed via OpenID configuration and bound to the issuer of the OpenID client
     */
    @Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
    @EachBean(DefaultOpenIdProviderMetadata.class)
    public JwksSignatureConfiguration createJwksSignatureConfiguration(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                                       @Parameter BeanProvider<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
        DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata = openIdProviderMetadata.get();
        JwksSignatureConfigurationProperties jwksSignatureConfiguration = new JwksSignatureConfigurationProperties(defaultOpenIdProviderMetadata.getName());
        jwksSignatureConfiguration.setUrl(defaultOpenIdProviderMetadata.getJwksUri());
        String issuer = issuer(openIdClientConfiguration, defaultOpenIdProviderMetadata);
        if (issuer == null || issuer.isBlank()) {
            LOG.warn("The JWKS of the OpenID client [{}] is not bound to an issuer because neither 'openid.issuer' is configured nor the provider metadata asserts one. Tokens signed with its keys are accepted whatever their 'iss' claim. Set 'micronaut.security.oauth2.clients.{}.openid.issuer', in particular when several providers are trusted.", defaultOpenIdProviderMetadata.getName(), defaultOpenIdProviderMetadata.getName());
        } else {
            jwksSignatureConfiguration.setIssuer(issuer);
        }
        return jwksSignatureConfiguration;
    }

    /**
     * The issuer asserted by the provider metadata is the value providers put in the {@code iss} claim, so it is preferred.
     * The configured issuer may be only the discovery URL (e.g. Oracle IDCS), which differs from the {@code iss} claim and
     * is therefore only used if the metadata does not assert an issuer (e.g. {@code fetch-configuration: false}).
     *
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @return The issuer asserted by the provider metadata or, if none, the issuer configured for the OpenID client
     */
    @Nullable
    static String issuer(@NonNull OpenIdClientConfiguration openIdClientConfiguration,
                         @NonNull OpenIdProviderMetadata openIdProviderMetadata) {
        String asserted = openIdProviderMetadata.getIssuer();
        if (asserted != null && !asserted.isBlank()) {
            return asserted;
        }
        return openIdClientConfiguration.getIssuer().map(URL::toString).orElse(null);
    }
}
