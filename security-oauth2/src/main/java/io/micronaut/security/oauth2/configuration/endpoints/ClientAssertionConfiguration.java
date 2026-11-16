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
package io.micronaut.security.oauth2.configuration.endpoints;

import org.jspecify.annotations.NonNull;

import java.time.Duration;
import java.util.Optional;

/**
 * JWT client assertion configuration for token endpoint authentication.
 *
 * @since 5.1.0
 */
public interface ClientAssertionConfiguration {

    /**
     * Default assertion lifetime.
     */
    Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);

    /**
     * Default JWS algorithm used for {@code client_secret_jwt}.
     */
    String DEFAULT_SIGNING_ALGORITHM = "HS256";

    /**
     * @return The assertion lifetime.
     */
    @NonNull
    Duration getLifetime();

    /**
     * @return The optional assertion audience. Defaults to the token endpoint URL.
     */
    @NonNull
    Optional<String> getAudience();

    /**
     * @return The optional assertion issuer. Defaults to the OAuth client id.
     */
    @NonNull
    Optional<String> getIssuer();

    /**
     * @return The optional assertion subject. Defaults to the OAuth client id.
     */
    @NonNull
    Optional<String> getSubject();

    /**
     * @return The optional JWS signing algorithm used for {@code client_secret_jwt}.
     */
    @NonNull
    Optional<String> getSigningAlgorithm();

    /**
     * @return The optional signer bean name used for {@code private_key_jwt}.
     */
    @NonNull
    Optional<String> getSignerName();
}
