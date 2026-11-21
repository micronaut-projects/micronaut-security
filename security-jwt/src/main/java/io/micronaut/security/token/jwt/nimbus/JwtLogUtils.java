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
import org.jspecify.annotations.Nullable;

import java.text.ParseException;

/**
 * Utility methods to describe a JWT in log statements without leaking the token itself or its claim values.
 * Only the {@code kid} and {@code alg} header parameters and the {@code jti} claim, if present, are included.
 * <p>
 * These values are read from a token which may not have been verified yet, so they are controlled by whoever sent it:
 * control characters (for example line breaks, which would allow forging log entries) are replaced and long values are truncated.
 * </p>
 *
 * @author Sergio del Amo
 * @since 5.5.3
 */
@Internal
final class JwtLogUtils {

    private static final int MAX_LENGTH = 128;
    private static final char REPLACEMENT = '_';
    private static final String TRUNCATED = "...";
    private static final char LINE_SEPARATOR = 0x2028;
    private static final char PARAGRAPH_SEPARATOR = 0x2029;

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
        return "JWT [kid=" + sanitize(jwt.getHeader().getKeyID())
                + ", alg=" + sanitize(jwt.getHeader().getAlgorithm().getName())
                + ", jti=" + sanitize(jti) + "]";
    }

    /**
     * @param value A value read from a JWT which may not have been verified
     * @return The value with control and line separator characters replaced by {@value #REPLACEMENT} and truncated to {@value #MAX_LENGTH} characters, or {@code null} if the value is {@code null}.
     */
    @Nullable
    static String sanitize(@Nullable String value) {
        if (value == null) {
            return null;
        }
        int length = Math.min(value.length(), MAX_LENGTH);
        StringBuilder sb = new StringBuilder(length + TRUNCATED.length());
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            sb.append(Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR ? REPLACEMENT : c);
        }
        if (value.length() > MAX_LENGTH) {
            sb.append(TRUNCATED);
        }
        return sb.toString();
    }
}
