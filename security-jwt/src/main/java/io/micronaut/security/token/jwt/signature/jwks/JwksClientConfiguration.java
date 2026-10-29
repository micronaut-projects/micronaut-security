/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.core.annotation.NonNull;

import java.time.Duration;

/**
 * Configuration for the retrieval of remote JSON Web Key Sets.
 *
 * @author Sergio del Amo
 * @since 3.11.3
 */
public interface JwksClientConfiguration {

    /**
     * How long a remote JWK Set is not requested again after a retrieval failed or returned no keys.
     * A zero or negative duration disables the back-off.
     *
     * @return The failure back-off duration.
     */
    @NonNull
    Duration getFailureBackoff();

    /**
     * How long a remote JWK Set retrieval may take before it is given up and treated as a failure.
     * It is applied as the connect timeout and the read timeout of the HTTP retrieval.
     * A zero or negative duration disables the timeout.
     *
     * @return The retrieval timeout.
     */
    @NonNull
    Duration getRetrievalTimeout();
}
