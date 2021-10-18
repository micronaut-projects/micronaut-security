/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.jwt.generator.claims;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;

import java.util.Map;

/**
 * Adapts from {@link ClaimsGenerator} to {@link io.micronaut.security.token.claims.ClaimsGenerator}.
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Internal
@Deprecated
public class ClaimsGeneratorAdapter implements io.micronaut.security.token.claims.ClaimsGenerator {

    private final ClaimsGenerator claimsGenerator;
    public ClaimsGeneratorAdapter(ClaimsGenerator claimsGenerator) {
        this.claimsGenerator = claimsGenerator;
    }

    @Override
    public Map<String, Object> generateClaims(Authentication authentication, Integer expiration) {
        return claimsGenerator.generateClaims(authentication, expiration);
    }

    @Override
    public Map<String, Object> generateClaimsSet(Map<String, ?> oldClaims, Integer expiration) {
        return claimsGenerator.generateClaimsSet(oldClaims, expiration);
    }
}
