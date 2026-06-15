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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;

/**
 * Exception thrown when a {@link DatabaseAccessTokenFetcher} cannot obtain a database access token.
 *
 * <p>This exception is the public failure type for database access token retrieval.
 * Implementations should wrap transport, response decoding, interruption, and provider
 * configuration failures in this type so callers do not depend on a specific HTTP client.
 */
@Experimental
@Internal
class DatabaseAccessTokenFetcherException extends RuntimeException {

    /**
     * @param message failure message
     */
    DatabaseAccessTokenFetcherException(@NonNull String message) {
        super(message);
    }

    /**
     * @param message failure message
     * @param cause original failure
     */
    DatabaseAccessTokenFetcherException(@NonNull String message, @NonNull Throwable cause) {
        super(message, cause);
    }
}
