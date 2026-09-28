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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

/**
 * Factory to create {@link ReactiveJwksSignature} beans for the {@link OpenIdProviderMetadata#getJwksUri()} of OpenID clients.
 *
 * @author Sergio del Amo
 * @since 1.3.0
 */
@Factory
@Internal
public class JwksUriSignatureFactory {
    private static final Logger LOG = LoggerFactory.getLogger(JwksUriSignatureFactory.class);

    /**
     * The returned configuration resolves the JWKS URI lazily, so that it can be created even if the OpenID provider metadata
     * could not be fetched yet; the metadata is resolved when the JWKS URI is first needed.
     *
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @return a {@link JwksSignatureConfiguration} pointed to the jwks_uri exposed via OpenID configuration
     */
    @EachBean(DefaultOpenIdProviderMetadata.class)
    public JwksSignatureConfiguration createJwksSignatureConfiguration(@Parameter @Nullable OpenIdClientConfiguration openIdClientConfiguration,
                                                                       @Parameter BeanProvider<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
        String name = openIdClientConfiguration != null ? openIdClientConfiguration.getName() : openIdProviderMetadata.get().getName();
        return new OpenIdProviderMetadataJwksSignatureConfiguration(name, SupplierUtil.memoized(openIdProviderMetadata::get));
    }

    /**
     * {@link JwksSignatureConfiguration} backed by the lazily resolved {@link DefaultOpenIdProviderMetadata} of an OpenID provider.
     */
    @Internal
    static final class OpenIdProviderMetadataJwksSignatureConfiguration implements JwksSignatureConfiguration {
        private final String name;
        private final Supplier<DefaultOpenIdProviderMetadata> openIdProviderMetadata;

        OpenIdProviderMetadataJwksSignatureConfiguration(String name, Supplier<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
            this.name = name;
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

        @Override
        @NonNull
        public KeyType getKeyType() {
            return JwksSignatureConfigurationProperties.DEFAULT_KEYTYPE;
        }

        @Override
        @NonNull
        @Deprecated(forRemoval = true, since = "4.11.0")
        @SuppressWarnings("removal")
        public Integer getCacheExpiration() {
            return JwksSignatureConfigurationProperties.DEFAULT_CACHE_EXPIRATION;
        }
    }
}
