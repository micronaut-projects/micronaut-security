/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.config;

import dev.paseto.jpaseto.Version;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Named;

import javax.crypto.SecretKey;
import javax.validation.constraints.NotNull;

/**
 * @author Sergio del Amo
 * @since 3.1.0
 */
@Requires(property = PasetoConfigurationProperties.PREFIX + ".local-generator.base64-shared-secret")
@ConfigurationProperties(PasetoConfigurationProperties.PREFIX + ".local-generator")
@Named("local-generator")
public class LocalGeneratorConfigurationProperties implements VersionedSharedSecretConfiguration {

    public static final Version DEFAULT_VERSION = Version.V1;

    @NotNull
    @NonNull
    private Version version = DEFAULT_VERSION;

    @NonNull
    @NotNull
    private SecretKey base64SharedSecret;

    @Override
    @NonNull
    public Version getVersion() {
        return version;
    }

    /**
     * Paseto version. Defaults to v1.
     * @param version Paseto version
     */
    public void setVersion(@NonNull Version version) {
        this.version = version;
    }

    @Override
    @NonNull
    public SecretKey getSharedSecret() {
        return base64SharedSecret;
    }

    /**
     * shared secret used for Paseto token base64 encoded.
     * @param base64SharedSecret shared secret used for Paseto token base64 encoded.
     */
    public void setBase64SharedSecret(@NonNull SecretKey base64SharedSecret) {
        this.base64SharedSecret = base64SharedSecret;
    }
}
