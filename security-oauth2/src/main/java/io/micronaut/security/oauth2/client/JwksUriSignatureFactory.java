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

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.function.Supplier;

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
     * The returned configuration resolves the JWKS URI and the issuer lazily, so that it can be created even if the OpenID provider metadata
     * could not be fetched yet; the metadata is resolved when the JWKS URI is first needed.
     *
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @return a {@link JwksSignatureConfiguration} pointed to the jwks_uri exposed via OpenID configuration and bound to the issuer of the OpenID client
     */
    @Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
    @EachBean(DefaultOpenIdProviderMetadata.class)
    public JwksSignatureConfiguration createJwksSignatureConfiguration(@Parameter @Nullable OpenIdClientConfiguration openIdClientConfiguration,
                                                                       @Parameter BeanProvider<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
        String name = openIdClientConfiguration != null ? openIdClientConfiguration.getName() : openIdProviderMetadata.get().getName();
        return new OpenIdProviderMetadataJwksSignatureConfiguration(name, openIdClientConfiguration, SupplierUtil.memoized(openIdProviderMetadata::get));
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

    /**
     * {@link JwksSignatureConfiguration} backed by the lazily resolved {@link DefaultOpenIdProviderMetadata} of an OpenID provider.
     */
    @Internal
    static final class OpenIdProviderMetadataJwksSignatureConfiguration implements JwksSignatureConfiguration {
        private final String name;
        @Nullable
        private final OpenIdClientConfiguration openIdClientConfiguration;
        private final Supplier<DefaultOpenIdProviderMetadata> openIdProviderMetadata;
        private volatile boolean unboundIssuerWarned;

        OpenIdProviderMetadataJwksSignatureConfiguration(String name,
                                                         @Nullable OpenIdClientConfiguration openIdClientConfiguration,
                                                         Supplier<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
            this.name = name;
            this.openIdClientConfiguration = openIdClientConfiguration;
            this.openIdProviderMetadata = openIdProviderMetadata;
        }

        @Override
        @NonNull
        public String getName() {
            return name;
        }

        /**
         * @return The JWKS URI exposed by the OpenID provider metadata, or {@code null} if the provider does not expose one or its metadata cannot be resolved at the moment.
         */
        @Override
        public String getUrl() {
            try {
                return openIdProviderMetadata.get().getJwksUri();
            } catch (RuntimeException e) {
                // the fetcher logs the underlying failure at ERROR, rate-limited by its back-off
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The JWKS URI of provider [{}] is unavailable because its OpenID provider metadata could not be resolved: {}", name, e.getMessage());
                }
                return null;
            }
        }

        /**
         * @return {@code null}, keys of any type are matched.
         */
        @Override
        @Nullable
        public KeyType getKeyType() {
            return null;
        }

        @Override
        @NonNull
        @Deprecated(forRemoval = true, since = "4.11.0")
        @SuppressWarnings("removal")
        public Integer getCacheExpiration() {
            return JwksSignatureConfigurationProperties.DEFAULT_CACHE_EXPIRATION;
        }

        /**
         * @return The issuer the key set is bound to. If the OpenID provider metadata cannot be resolved at the moment, the issuer configured for the OpenID client.
         */
        @Override
        @Nullable
        public String getIssuer() {
            String issuer;
            try {
                DefaultOpenIdProviderMetadata metadata = openIdProviderMetadata.get();
                issuer = openIdClientConfiguration != null ? issuer(openIdClientConfiguration, metadata) : metadata.getIssuer();
            } catch (RuntimeException e) {
                // without metadata there is no JWKS URI either, so no token is verified with this key set
                return openIdClientConfiguration != null ? openIdClientConfiguration.getIssuer().map(URL::toString).orElse(null) : null;
            }
            if (issuer == null || issuer.isBlank()) {
                if (!unboundIssuerWarned) {
                    unboundIssuerWarned = true;
                    LOG.warn("The JWKS of the OpenID client [{}] is not bound to an issuer because neither 'openid.issuer' is configured nor the provider metadata asserts one. Tokens signed with its keys are accepted whatever their 'iss' claim. Set 'micronaut.security.oauth2.clients.{}.openid.issuer', in particular when several providers are trusted.", name, name);
                }
                return null;
            }
            return issuer;
        }
    }
}
