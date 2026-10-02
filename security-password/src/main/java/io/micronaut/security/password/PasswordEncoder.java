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
package io.micronaut.security.password;

/**
 * Encodes passwords for storage and verifies a password against a stored encoding.
 *
 * <p>Implementations must honour the following contract:</p>
 * <ul>
 * <li>The encoding is a salted, one-way hash. Encoding the same password twice produces different
 * results, and the encoding never contains the raw password.</li>
 * <li>Every character of the raw password is significant. Implementations must not truncate the
 * password or alter its whitespace or case.</li>
 * <li>A blank raw password, one that is empty or contains only whitespace, is never encoded.
 * {@link #encode(String)} throws an {@link IllegalArgumentException} for it, and
 * {@link #matches(String, String)} returns {@code false}.</li>
 * <li>{@link #matches(String, String)} returns {@code false}, instead of throwing an exception, for
 * an encoded password that the implementation cannot parse.</li>
 * <li>Implementations are safe for use by multiple threads.</li>
 * </ul>
 *
 * @since 5.5.0
 */
public interface PasswordEncoder {

    /**
     * Encodes a raw password for storage.
     *
     * @param rawPassword the raw password
     * @return the encoded password, which includes the salt and any parameters required to verify it
     * @throws IllegalArgumentException if the raw password is blank
     */
    String encode(String rawPassword);

    /**
     * Verifies a raw password against an encoded password.
     *
     * @param rawPassword the raw password to verify
     * @param encodedPassword the encoded password, as returned by {@link #encode(String)}
     * @return {@code true} if the raw password matches the encoded password
     */
    boolean matches(String rawPassword, String encodedPassword);
}
