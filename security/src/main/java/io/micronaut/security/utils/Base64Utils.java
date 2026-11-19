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

import java.util.Base64;

@Internal
public final class Base64Utils {

    private static final String EQUALS = "=";

    private Base64Utils() {
    }


    /**
     * Decodes a Base64 encoded String into a newly-allocated byte array
     * using the {@link Base64} encoding scheme.
     *
     * <p> An invocation of this method has exactly the same effect as invoking
     * {@code decode(src.getBytes(StandardCharsets.ISO_8859_1))}
     *
     * @param   src
     *          the string to decode
     *
     * @return  A newly-allocated byte array containing the decoded bytes.
     *
     * @throws  IllegalArgumentException
     *          if {@code src} is not in valid Base64 scheme
     */
    public static byte[] decode(String src) {
        // Padding is only legal when it completes the final four character unit.
        if (src.endsWith(EQUALS) && src.length() % 4 != 0) {
            throw new IllegalArgumentException("Invalid Base 64 padding");
        }
        return Base64.getDecoder().decode(src);
    }
}
