/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.generator.claims;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Utsav Varia
 * @since 3.0
 */
public final class PasetoClaimsSet {

    private final Map<String, Object> claims = new LinkedHashMap<>();

    private PasetoClaimsSet(Map<String, Object> claims) {
        this.claims.putAll(claims);
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * Builder for creating Paseto Claims builder.
     */
    public static class Builder {

        /**
         * The claims.
         */
        private final Map<String, Object> claims = new LinkedHashMap<>();

        /**
         * Gives the claims map.
         *
         * @return claims map
         */
        public PasetoClaimsSet build() {
            return new PasetoClaimsSet(claims);
        }

        /**
         * Set the specified claim.
         *
         * @param name  The name of the claim to set. Must not be {@code null}
         * @param value The value of the claim to set, {@code null} jf not specified
         * @return this builder.
         */
        public Builder claim(final String name, final Object value) {
            claims.put(name, value);
            return this;
        }

    }

}
