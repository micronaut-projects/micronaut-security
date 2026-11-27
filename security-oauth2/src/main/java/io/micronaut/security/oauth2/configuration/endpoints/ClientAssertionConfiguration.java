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
 * Configuration of the client assertion used for {@code private_key_jwt} client authentication.
 *
 * <p>Two signing options are supported, selected by {@link #isRemoteSigningEnabled()}:</p>
 * <ul>
 *   <li><b>Local signing</b> (default): {@link #getPrivateKey()} is a PEM-encoded private key used to sign the
 *       assertion and {@link #getKeyId()} is sent as the JWT {@code kid} header.</li>
 *   <li><b>Remote signing</b>: {@link #getKeyName()} names the key held by a remote signer (for example a KMS or HSM)
 *       and signing is delegated to a user-provided
 *       {@link io.micronaut.security.oauth2.endpoint.token.request.clientauth.ClientAssertionGenerator} bean.</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 5.5.3
 */
public interface ClientAssertionConfiguration {

    /**
     * Default lifetime of the client assertion JWT.
     */
    Duration DEFAULT_LIFETIME = Duration.ofSeconds(60);

    /**
     * Default signing algorithm.
     */
    String DEFAULT_ALGORITHM = "RS256";

    /**
     * @return The JWS algorithm used to sign the client assertion (for example {@code RS256} or {@code ES256}).
     */
    @NonNull
    default String getAlgorithm() {
        return DEFAULT_ALGORITHM;
    }

    /**
     * @return The lifetime of the client assertion JWT.
     */
    @NonNull
    default Duration getLifetime() {
        return DEFAULT_LIFETIME;
    }

    /**
     * @return The authorization server's issuer identifier for non-OpenID clients. If empty, the OpenID issuer
     * identifier is used. When both are configured, they must match exactly.
     */
    default Optional<String> getAudience() {
        return Optional.empty();
    }

    /**
     * @return The PEM-encoded private key, or a resource path ({@code classpath:} or {@code file:}), used for local signing.
     */
    default Optional<String> getPrivateKey() {
        return Optional.empty();
    }

    /**
     * @return The JWT {@code kid} header value used for local signing.
     */
    default Optional<String> getKeyId() {
        return Optional.empty();
    }

    /**
     * @return The name of the key held by the remote signer. Only used when {@link #isRemoteSigningEnabled()} is {@code true}.
     */
    default Optional<String> getKeyName() {
        return Optional.empty();
    }

    /**
     * @return {@code true} if the client assertion is signed by a remote signer instead of a local private key.
     */
    default boolean isRemoteSigningEnabled() {
        return false;
    }
}
