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
package io.micronaut.security.token.paseto.generator.claims;

import dev.paseto.jpaseto.Claims;

import java.time.Instant;
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

    public Instant getNotBeforeTime() {
        Object value = claims.get(Claims.NOT_BEFORE);

        if (value == null) {
            return null;
        } else if (value instanceof Instant) {
            return (Instant) value;
        } else if (value instanceof Number) {
            return Instant.ofEpochSecond(((Number) value).longValue());
        } else {
            return null;
        }
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
         * Sets the issuer(iss) claim.
         *
         * @param iss The issuer claim.
         * @return This builder.
         */
        public Builder issuer(String iss) {
            claim(Claims.ISSUER, iss);
            return this;
        }

        /**
         * Sets the subject(sub) claim.
         *
         * @param sub The subject claim.
         * @return This builder.
         */
        public Builder subject(String sub) {
            claim(Claims.SUBJECT, sub);
            return this;
        }

        /**
         * Sets the audience(aud) claim.
         *
         * @param aud The audience claim.
         * @return This builder.
         */
        public Builder audience(String aud) {
            claim(Claims.AUDIENCE, aud);
            return this;
        }

        /**
         * Sets the expiery(exp) claim.
         *
         * @param exp The expiry claim.
         * @return This builder.
         */
        public Builder expiration(Instant exp) {
            claim(Claims.EXPIRATION, exp);
            return this;
        }

        /**
         * Sets not before(nbf) claim.
         *
         * @param nbf not before claim.
         * @return This builder.
         */
        public Builder notBefore(Instant nbf) {
            claim(Claims.NOT_BEFORE, nbf);
            return this;
        }

        /**
         * Sets the issued at(iat) claim.
         *
         * @param iat The issued at claim.
         * @return This builder.
         */
        public Builder issuedAt(Instant iat) {
            claim(Claims.ISSUED_AT, iat);
            return this;
        }

        /**
         * Sets the token id(jti) claim.
         *
         * @param jti The token id claim.
         * @return This builder.
         */
        public Builder tokenId(String jti) {
            claim(Claims.TOKEN_ID, jti);
            return this;
        }

        //TODO:  Add Support for footer in token

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
