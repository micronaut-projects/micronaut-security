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

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import javax.inject.Provider;

/**
 * Factory to create {@link JwksSignature} beans for the {@link OpenIdProviderMetadata#getJwksUri()} of OpenID clients.
 *
 * @author Sergio del Amo
 * @since 1.3.0
 */
@Factory
@Internal
public class JwksUriSignatureFactory {

    /**
     *
     * @param openIdProviderMetadata The open id provider metadata
     * @param jwkValidator JWK Validator
     * @return a {@link JwksSignature} pointed to the jwks_uri exposed via OpenID configuration
     */
    @Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
    @EachBean(DefaultOpenIdProviderMetadata.class)
    public JwksSignature createJwksUriSignature(@Parameter Provider<DefaultOpenIdProviderMetadata> openIdProviderMetadata,
                                                JwkValidator jwkValidator) {
        return new JwksSignature(new JwksSignatureConfiguration() {
            @NonNull
            @Override
            public String getUrl() {
                return openIdProviderMetadata.get().getJwksUri();
            }

            @Nullable
            @Override
            public KeyType getKeyType() {
                return null;
            }
        }, jwkValidator);
    }
}
