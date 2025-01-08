/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.generator;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;

/**
 * CSRF token Generation with HMAC.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> request
 */
@Internal
public interface CsrfHmacTokenGenerator<T> extends CsrfTokenGenerator<T> {
    /**
     * Dot is used as separator between the HMAC and the random value. As the random value and hmac are base64 encoded, they will not contain a dot.
     */
    String HMAC_RANDOM_SEPARATOR = ".";

    /**
     * Generates an HMAC.
     * @param request Request
     * @param base64EncodedRandomValue Cryptographic random value encoded as Base64
     * @return HMAC hash
     */
    @NonNull
    String hmac(@NonNull T request, @NonNull String base64EncodedRandomValue);
}
