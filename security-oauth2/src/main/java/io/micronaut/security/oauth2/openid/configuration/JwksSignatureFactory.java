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
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import javax.annotation.Nonnull;
import javax.inject.Singleton;

/**
 * {@link Factory} to create {@link JwksSignature} for an OpenID Configuration.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = JwksSignatureFactoryConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(beans = {OpenIdConfiguration.class, JwksSignatureFactoryConfiguration.class})
@Factory
public class JwksSignatureFactory {

    private final OpenIdConfiguration openIdConfiguration;
    private final JwksSignatureFactoryConfiguration jwksSignatureFactoryConfiguration;
    private final JwkValidator jwkValidator;

    /**
     * @param jwksSignatureFactoryConfiguration JWKS Signature Factory Configuration
     * @param openIdConfiguration Open ID Configuration
     * @param jwkValidator JSON Web Key Validator
     */
    public JwksSignatureFactory(OpenIdConfiguration openIdConfiguration,
                                JwksSignatureFactoryConfiguration jwksSignatureFactoryConfiguration,
                                JwkValidator jwkValidator) {
        this.openIdConfiguration = openIdConfiguration;
        this.jwksSignatureFactoryConfiguration = jwksSignatureFactoryConfiguration;
        this.jwkValidator = jwkValidator;
    }

    /**
     *
     * @return a bean of type {@link JwksSignature}
     */
    @Bean
    @Singleton
    public JwksSignature jwsk() {
        return new JwksSignature(new JwksSignatureConfiguration() {
            @Nonnull
            @Override
            public String getUrl() {
                return openIdConfiguration.getJwksUri();
            }

            @Nonnull
            @Override
            public KeyType getKeyType() {
                return jwksSignatureFactoryConfiguration.getKeyType();
            }
        }, jwkValidator);
    }
}
