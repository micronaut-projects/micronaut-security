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
package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Utils class to instantiate a JWClaimsSet give a map of claims.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public class JWTClaimsSetUtils {

    private JWTClaimsSetUtils() {
    }

    /**
     *
     * @param claims JWT claims
     * @return A JWTClaimsSet
     */
    public static JWTClaimsSet jwtClaimsSetFromClaims(JwtClaims claims) {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        for (String k : claims.names()) {
            claimsSetBuilder.claim(k, claims.get(k));
        }
        return claimsSetBuilder.build();
    }
}
