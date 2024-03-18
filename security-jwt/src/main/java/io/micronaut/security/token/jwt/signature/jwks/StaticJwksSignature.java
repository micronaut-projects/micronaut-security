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
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.io.ResourceResolver;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Optional;

/**
 * Creates a {@link io.micronaut.security.token.jwt.signature.SignatureConfiguration} per bean of type {@link StaticJwksSignatureConfiguration}.
 */
@Requires(bean = ResourceResolver.class)
@EachBean(StaticJwksSignatureConfiguration.class)
public class StaticJwksSignature extends JWKSetJwksSignature {

    public StaticJwksSignature(StaticJwksSignatureConfiguration staticJwksSignatureConfiguration,
                               ResourceResolver resourceResolver,
                               JwkValidator jwkValidator) {
        super(jwkValidator, jwkSet(staticJwksSignatureConfiguration, resourceResolver));
    }

    @NonNull
    private static JWKSet jwkSet(StaticJwksSignatureConfiguration staticJwksSignatureConfiguration,
                                 ResourceResolver resourceResolver) throws ConfigurationException {
        Optional<InputStream> inputStreamOptional = resourceResolver.getResourceAsStream(staticJwksSignatureConfiguration.getPath());
        if (!inputStreamOptional.isPresent()) {
            throw new ConfigurationException("could not load resource for path " + staticJwksSignatureConfiguration.getPath());
        }
        InputStream inputStream = inputStreamOptional.get();
        try {
            return JWKSet.load(inputStream);
        } catch (IOException e) {
            throw new ConfigurationException("IOException loading JWKSet for resource at path " + staticJwksSignatureConfiguration.getPath());
        } catch (ParseException e) {
            throw new ConfigurationException("ParseException loading JWKSet for resource at path " + staticJwksSignatureConfiguration.getPath());
        }
    }
}
