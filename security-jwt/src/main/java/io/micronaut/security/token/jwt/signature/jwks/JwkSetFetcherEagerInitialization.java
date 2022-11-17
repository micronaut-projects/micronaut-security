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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Parallel;
import io.micronaut.context.annotation.Requires;

import java.util.Collection;

/**
 * Eagerly loads in parallel every remote JWKS on {@link io.micronaut.context.BeanContext} initialization.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Context
@Parallel
@Requires(beans = {JwksSignature.class, JwkSetFetcher.class})
class JwkSetFetcherEagerInitialization {

    /**
     * Eagerly loads in parallel every remote JWKS on {@link io.micronaut.context.BeanContext} initialization.
     * @param signatures JWKS signatures
     * @param jwkSetFetcher JWKSet Fetcher
     */
    JwkSetFetcherEagerInitialization(Collection<JwksSignature> signatures,
                                     JwkSetFetcher<?> jwkSetFetcher) {
        signatures.stream()
            .map(JwksSignature::getUrl)
            .forEach(jwkSetFetcher::fetch);
    }
}
