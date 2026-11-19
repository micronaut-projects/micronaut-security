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
package io.micronaut.security.utils;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;

import java.util.Base64;

/**
 * Base64 decoding that rejects malformed padding before it reaches the JDK decoder.
 *
 * <p>Some JDK versions corrupt the heap when the AVX-512 VBMI Base64 decode intrinsic receives input
 * whose final, incomplete four character unit ends with padding (CVE-2026-114938, "Java4Shell").
 * The JDK rejects such input with an {@link IllegalArgumentException}, but only after the out of bounds
 * write. Rejecting it here keeps attacker supplied values from reaching the intrinsic.</p>
 *
 * @author Sergio del Amo
 * @since 5.4.3
 */
@Internal
public final class Base64Utils {

    /**
     * Number of Base64 characters that encode three bytes.
     */
    private static final int UNIT_LENGTH = 4;

    private static final char PADDING = '=';

    private Base64Utils() {
    }

    /**
     * Decodes a String with the {@link Base64#getDecoder() basic Base64 decoder}.
     *
     * <p>Input that ends with padding but whose length is not a multiple of four is rejected before
     * it is passed to the JDK. The JDK decoder rejects that input as well, so the set of accepted inputs
     * and the decoded bytes are the same as with {@link Base64.Decoder#decode(String)}; only the
     * exception message differs.</p>
     *
     * @param src the Base64 encoded String to decode
     * @return A newly-allocated byte array containing the decoded bytes.
     * @throws IllegalArgumentException if {@code src} is not valid Base64
     */
    public static byte @NonNull [] decode(@NonNull String src) {
        if (!src.isEmpty() && src.charAt(src.length() - 1) == PADDING && src.length() % UNIT_LENGTH != 0) {
            throw new IllegalArgumentException("Invalid Base64 padding");
        }
        return Base64.getDecoder().decode(src);
    }
}
