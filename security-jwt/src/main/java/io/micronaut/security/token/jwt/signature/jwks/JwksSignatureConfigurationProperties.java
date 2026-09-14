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
import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;

/**
 * JSON Web Key Set (JWKS) Signature Configuration properties holder.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@EachProperty(JwksSignatureConfigurationProperties.PREFIX)
public class JwksSignatureConfigurationProperties implements JwksSignatureConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".signatures.jwks";

    /**
     * The key type used by default before 5.4.0.
     * @deprecated Not used. Since 5.4.0 no key type is configured by default, and keys of any key type are used to verify signatures.
     */
    @SuppressWarnings("WeakerAccess")
    @Deprecated(forRemoval = true, since = "5.4.0")
    public static final KeyType DEFAULT_KEYTYPE = KeyType.RSA;

    /**
     * The default cache expiration.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int DEFAULT_CACHE_EXPIRATION = 60;

    /**
     * The default minimum interval between two JWKS refreshes triggered by an unknown key ID.
     */
    @SuppressWarnings("WeakerAccess")
    public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofSeconds(30);

    @Nullable
    private final String name;

    @NonNull
    private Integer cacheExpiration = DEFAULT_CACHE_EXPIRATION;

    private String url;

    @Nullable
    private KeyType keyType;

    @NonNull
    private Duration refreshInterval = DEFAULT_REFRESH_INTERVAL;

    public JwksSignatureConfigurationProperties(@Parameter String name) {
        this.name = name;
    }

    @Override
    @NonNull
    public String getName() {
        return name;
    }

    /**
     * @deprecated Not used. JWKS is cached via Micronaut Cache. You need an implementation of Micronaut Cache and the cache configuration micronaut.caches.jwks.expire-after-write
     * @return The number of seconds to cache the JWKS.
     */
    @Override
    @NonNull
    @Deprecated(forRemoval = true, since = "4.11.0")
    public Integer getCacheExpiration() {
        return cacheExpiration;
    }

    /**
     * JWKS cache expiration. Default value {@value #DEFAULT_CACHE_EXPIRATION} seconds.
     * @param cacheExpiration The expiration
     * @deprecated Not used. JWKS is cached via Micronaut Cache. You need an implementation of Micronaut Cache and the cache configuration micronaut.caches.jwks.expire-after-write
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public void setCacheExpiration(Integer cacheExpiration) {
        ArgumentUtils.requireNonNull("cacheExpiration", cacheExpiration);
        this.cacheExpiration = cacheExpiration;
    }

    /**
     *
     * @return URL to the remote JSON Web Key Set.
     */
    @Override
    @NotNull
    @NonNull
    public String getUrl() {
        return url;
    }

    /**
     * Remote JSON Web Key set url. e.g. https://.../.well-known/jwks.json
     * @param url Remote JSON Web Key set url.
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     *
     * @return Representation the KeyType for this JWKS signature configuration. KeyType is the kty parameter in a JSON Web Key (JWK). {@code null} if keys of any key type may be used.
     */
    @Override
    @Nullable
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Key type (the kty parameter of a JSON Web Key, e.g. RSA or EC). If set, only keys of this type are used to verify JWT signatures. By default, it is not set and keys of any key type are used.
     * @param keyType Representation of the kty parameter in a JSON Web Key (JWK).
     */
    public void setKeyType(@Nullable KeyType keyType) {
        this.keyType = keyType;
    }

    /**
     *
     * @return Minimum interval between two JWKS refreshes triggered by a token whose key ID is not present in the cached JWKS.
     */
    @Override
    @NonNull
    public Duration getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * When a JWT carries a {@code kid} header which is not present in the cached JWKS, the JWKS cache is cleared and the JWKS is fetched again.
     * This property sets the minimum interval between two such refreshes. Default value 30 seconds.
     * @param refreshInterval Minimum interval between two JWKS refreshes triggered by an unknown key ID.
     */
    public void setRefreshInterval(@NonNull Duration refreshInterval) {
        ArgumentUtils.requireNonNull("refreshInterval", refreshInterval);
        this.refreshInterval = refreshInterval;
    }
}
