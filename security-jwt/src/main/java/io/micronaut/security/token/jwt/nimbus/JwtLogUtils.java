/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;

import java.text.ParseException;

/**
 * Utility methods to describe a JWT in log statements without leaking the token itself or its claim values.
 * Only the {@code kid} and {@code alg} header parameters and the {@code jti} claim, if present, are included.
 *
 * @author Sergio del Amo
 * @since 4.13.0
 */
@Internal
final class JwtLogUtils {

    private JwtLogUtils() {
    }

    /**
     * @param jwt Signed JWT
     * @return A description of the JWT containing only its {@code kid}, {@code alg} and {@code jti}, never the compact serialization or claim values.
     */
    @NonNull
    static String describe(@NonNull SignedJWT jwt) {
        String jti = null;
        try {
            if (jwt.getJWTClaimsSet() != null) {
                jti = jwt.getJWTClaimsSet().getJWTID();
            }
        } catch (ParseException e) {
            // claims could not be parsed, do not include jti
        }
        return "JWT [kid=" + jwt.getHeader().getKeyID() + ", alg=" + jwt.getHeader().getAlgorithm() + ", jti=" + jti + "]";
    }
}
