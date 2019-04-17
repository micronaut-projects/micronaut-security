/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.configuration;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.annotation.ConfigurationProperties;

/**
 * {@link ConfigurationProperties} implementation of {@link JwksSignatureFactoryConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(JwksSignatureFactoryConfigurationProperties.PREFIX)
public class JwksSignatureFactoryConfigurationProperties implements JwksSignatureFactoryConfiguration {

    public static final String PREFIX = OpenIdProviderConfigurationProperties.PREFIX + ".jwks-signature-factory";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;

    private KeyType keyType = KeyType.RSA;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables {@link JwksSignatureFactory}. Default value ({@value #DEFAULT_ENABLED}).
     * @param enabled enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * KeyType for this JWKS signature configuration. Default Value (RSA).
     * @param keyType KeyType for this JWKS signature configuration.
     */
    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }
}
