/*
 * Copyright 2017-2018 original authors
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
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import javax.annotation.Nonnull;
import javax.inject.Singleton;

@Requires(beans = {OpenIdConfiguration.class})
@Factory
public class JwksSignatureFactory {

    private final OpenIdConfiguration openIdConfiguration;

    public JwksSignatureFactory(OpenIdConfiguration openIdConfiguration) {
        this.openIdConfiguration = openIdConfiguration;
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
                return KeyType.RSA;
            }
        });
    }
}
