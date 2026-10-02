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

import io.micronaut.core.annotation.Experimental;
import jakarta.validation.constraints.NotBlank;

/**
 * Encodes passwords for storage and verifies a password against a stored encoding.
 *
 * <p>Implementations must honour the following contract:</p>
 * <ul>
 * <li>The encoding is a salted, one-way hash. Encoding the same password twice produces different
 * results, and the encoding never contains the raw password.</li>
 * <li>Every character of the raw password is significant. Implementations must not truncate the
 * password or alter its whitespace or case.</li>
 * <li>Blank values, which are {@code null}, empty or contain only whitespace, are rejected. The
 * parameters of {@link #encode(String)} and {@link #matches(String, String)} are constrained with
 * {@link NotBlank}, so an implementation that is a validated bean throws a
 * {@link jakarta.validation.ConstraintViolationException} for them.</li>
 * <li>{@link #matches(String, String)} returns {@code false}, instead of throwing an exception, for
 * an encoded password that is not blank and that the implementation cannot parse.</li>
 * <li>Implementations are safe for use by multiple threads.</li>
 * </ul>
 *
 * @since 5.5.0
 */
@Experimental
public interface PasswordEncoder {

    /**
     * Encodes a raw password for storage.
     *
     * @param rawPassword the raw password, which must not be blank
     * @return the encoded password, which includes the salt and any parameters required to verify it
     * @throws jakarta.validation.ConstraintViolationException if the raw password is blank
     */
    String encode(@NotBlank String rawPassword);

    /**
     * Verifies a raw password against an encoded password.
     *
     * <p>Both parameters are constrained with {@link NotBlank}. Callers that may hold a blank value,
     * for example for a user without a stored password, must check for it before calling this
     * method.</p>
     *
     * @param rawPassword the raw password to verify, which must not be blank
     * @param encodedPassword the encoded password, as returned by {@link #encode(String)}, which
     * must not be blank
     * @return {@code true} if the raw password matches the encoded password
     * @throws jakarta.validation.ConstraintViolationException if the raw password or the encoded
     * password is blank
     */
    boolean matches(@NotBlank String rawPassword, @NotBlank String encodedPassword);
}
