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
package io.micronaut.security.password.argon2;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An Argon2id hash in the PHC string format:
 * {@code $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>}.
 *
 * <p>Parsing is strict. Only Argon2id version 19 is accepted, the parameters must appear in the
 * order {@code m,t,p} as decimals without leading zeros, and the salt and hash must be canonical
 * unpadded Base64. The optional {@code keyid} and {@code data} parameters are not supported.</p>
 *
 * @param memory the memory cost, in kibibytes
 * @param iterations the number of iterations
 * @param parallelism the degree of parallelism
 * @param salt the salt
 * @param hash the hash
 * @see <a href="https://github.com/C2SP/C2SP/blob/main/phc-strings.md">PHC string format</a>
 * @since 5.5.0
 */
@Internal
public record Argon2PhcString(long memory, long iterations, int parallelism, byte[] salt, byte[] hash) {

    /** Lowest memory cost, in kibibytes, that Argon2 accepts for each degree of parallelism. */
    public static final int MEMORY_PER_LANE = 8;
    /** Highest degree of parallelism allowed by the PHC string format. */
    public static final int MAX_PARALLELISM = 255;
    /** Shortest salt, in bytes, allowed by the PHC string format. */
    public static final int MIN_SALT_LENGTH = 8;
    /** Longest salt, in bytes, allowed by the PHC string format. */
    public static final int MAX_SALT_LENGTH = 48;
    /** Shortest hash, in bytes, allowed by the PHC string format. */
    public static final int MIN_HASH_LENGTH = 12;
    /** Longest hash, in bytes, allowed by the PHC string format. */
    public static final int MAX_HASH_LENGTH = 64;

    private static final String PREFIX = "$argon2id$v=19$";
    // 11 to 64 Base64 characters hold 8 to 48 bytes; 16 to 86 characters hold 12 to 64 bytes.
    private static final Pattern PATTERN = Pattern.compile(
        "\\$argon2id\\$v=19\\$m=([1-9]\\d{0,9}),t=([1-9]\\d{0,9}),p=([1-9]\\d{0,2})\\$([A-Za-z0-9+/]{11,64})\\$([A-Za-z0-9+/]{16,86})");
    private static final int BASE64_GROUP_LENGTH = 4;
    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    /**
     * Parses an Argon2id PHC string.
     *
     * @param encoded the PHC string
     * @return the parsed string, or {@code null} if it is not a conforming Argon2id PHC string
     */
    public static @Nullable Argon2PhcString parse(String encoded) {
        Matcher matcher = PATTERN.matcher(encoded);
        if (!matcher.matches()) {
            return null;
        }
        int parallelism = Integer.parseInt(matcher.group(3));
        byte[] salt = decode(matcher.group(4));
        byte[] hash = decode(matcher.group(5));
        if (parallelism > MAX_PARALLELISM || salt == null || hash == null) {
            return null;
        }
        return new Argon2PhcString(Long.parseLong(matcher.group(1)), Long.parseLong(matcher.group(2)), parallelism, salt, hash);
    }

    /**
     * Formats an Argon2id hash as a PHC string.
     *
     * @param memory the memory cost, in kibibytes
     * @param iterations the number of iterations
     * @param parallelism the degree of parallelism
     * @param salt the salt
     * @param hash the hash
     * @return the PHC string
     */
    public static String format(int memory, int iterations, int parallelism, byte[] salt, byte[] hash) {
        return PREFIX + "m=" + memory + ",t=" + iterations + ",p=" + parallelism
            + '$' + ENCODER.encodeToString(salt) + '$' + ENCODER.encodeToString(hash);
    }

    private static byte @Nullable [] decode(String base64) {
        if (base64.length() % BASE64_GROUP_LENGTH == 1) {
            return null;
        }
        byte[] decoded = DECODER.decode(base64);
        return ENCODER.encodeToString(decoded).equals(base64) ? decoded : null;
    }
}
