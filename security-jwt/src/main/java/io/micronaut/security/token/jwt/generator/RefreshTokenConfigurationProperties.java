/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.generator;

import com.nimbusds.jose.JWSAlgorithm;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

/**
 * {@link ConfigurationProperties} implementation of {@link RefreshTokenConfiguration} to configure {@link SignedRefreshTokenGenerator}.
 *
 * @author James Kleeh
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Introspected
@Requires(property = RefreshTokenConfigurationProperties.PREFIX + ".secret")
@Requires(property = RefreshTokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@ConfigurationProperties(RefreshTokenConfigurationProperties.PREFIX)
public class RefreshTokenConfigurationProperties implements RefreshTokenConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".generator.refresh-token";

    /**
     * The default secure value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final JWSAlgorithm DEFAULT_JWS_ALGORITHM = JWSAlgorithm.HS256;

    /**
     * The default base64 value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_BASE64 = false;

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;

    @NonNull
    @NotNull
    private JWSAlgorithm jwsAlgorithm = DEFAULT_JWS_ALGORITHM;

    @NonNull
    @NotBlank
    private String secret;

    private boolean base64 = DEFAULT_BASE64;

    /**
     * Sets whether {@link io.micronaut.security.token.jwt.generator.SignedRefreshTokenGenerator} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * {@link com.nimbusds.jose.JWSAlgorithm}. Defaults to HS256
     *
     * @param jwsAlgorithm JWS Algorithm
     */
    public void setJwsAlgorithm(@NonNull JWSAlgorithm jwsAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
    }

    /**
     * @param secret shared secret. For HS256 must be at least 256 bits.
     */
    public void setSecret(@NonNull String secret) {
        this.secret = secret;
    }

    /**
     * Indicates whether the supplied secret is base64 encoded. Default value {@value #DEFAULT_BASE64}.
     *
     * @param base64 boolean flag indicating whether the supplied secret is base64 encoded
     */
    public void setBase64(boolean base64) {
        this.base64 = base64;
    }

    @NonNull
    @Override
    public JWSAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm;
    }

    @NonNull
    @Override
    public String getSecret() {
        return secret;
    }

    @Override
    public boolean isBase64() {
        return base64;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
