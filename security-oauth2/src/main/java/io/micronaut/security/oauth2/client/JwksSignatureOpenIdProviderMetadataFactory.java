/*
 * Copyright 2017-2022 original authors
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

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;

/**
 * Creates a {@link JwksSignature} for each bean of type {@link OpenIdProviderMetadata} which defines a jwks_uri.
 * @since 3.9.0
 * @author sdelamo
 */
@Factory
public class JwksSignatureOpenIdProviderMetadataFactory {

    @EachBean(OpenIdProviderMetadata.class)
    JwksSignature createJwksSignature(OpenIdProviderMetadata openIdProviderMetadata,
                                      JwkValidator jwkValidator,
                                      JwkSetFetcher<JWKSet> jwkSetFetcher) {
        if (StringUtils.isEmpty(openIdProviderMetadata.getJwksUri())) {
            throw new DisabledBeanException("Could not create a bean of type JwksSignature. JWKS URI is not set for OpenID Provider " + openIdProviderMetadata.getIssuer());
        }
        JwksSignatureConfigurationProperties config = new JwksSignatureConfigurationProperties();
        config.setUrl(openIdProviderMetadata.getJwksUri());
        return new JwksSignature(config, jwkValidator, jwkSetFetcher);
    }
}
