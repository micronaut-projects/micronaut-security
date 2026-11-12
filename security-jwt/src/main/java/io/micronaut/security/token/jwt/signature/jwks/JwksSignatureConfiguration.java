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

import com.nimbusds.jose.jwk.KeyType;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.naming.Named;

import java.time.Duration;

/**
 * JSON Web Key Set Configuration.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface JwksSignatureConfiguration extends Named {

    /**
     * Json Web Key Set endpoint url.
     * @return returns a url where a JWKS is exposed.
     */
    @NonNull
    String getUrl();

    /**
     * Representation the KeyType for this JWKS signature configuration. KeyType is the kty parameter in a JSON Web Key (JWK).
     * When a key type is returned, only keys of that type are used to verify token signatures; a token signed with a key of
     * another type is not verified, even if that key is part of the JWKS.
     * @return The KeyType for the JWKS signature configuration, or {@code null} if keys of any type are matched.
     */
    @Nullable
    KeyType getKeyType();

    /**
     * @deprecated Not used. JWKS is cached via Micronaut Cache. You need an implementation of Micronaut Cache and the cache configuration micronaut.caches.jwks.expire-after-write
     * @return The number of seconds to cache the JWKS.
     */
    @NonNull
    @Deprecated(forRemoval = true, since = "4.11.0")
    Integer getCacheExpiration();

    /**
     * Minimum interval between two forced refreshes of the cached JWKS triggered by a token whose {@code kid} is not present in the cached key set.
     * @return The minimum interval between two refreshes triggered by an unknown key ID.
     * @since 5.4.0
     */
    @NonNull
    default Duration getRefreshInterval() {
        return JwksSignatureConfigurationProperties.DEFAULT_REFRESH_INTERVAL;
    }

    /**
     * The issuer this JSON Web Key Set is bound to. When an issuer is set, a token is only verified with this key set if
     * its {@code iss} claim matches the issuer, even if its signature validates against one of the keys. This prevents a
     * key trusted for one identity provider from signing tokens that claim to be issued by another provider.
     * @return The issuer the key set is bound to, or {@code null} if tokens are verified regardless of their {@code iss} claim.
     * @since 5.5.2
     */
    @Nullable
    default String getIssuer() {
        return null;
    }
}
