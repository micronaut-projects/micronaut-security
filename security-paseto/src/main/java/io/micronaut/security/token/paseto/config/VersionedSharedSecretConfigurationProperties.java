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
import io.micronaut.core.annotation.NonNull;
import javax.crypto.SecretKey;
import javax.validation.constraints.NotNull;

/**
 * @author Sergio del Amo
 * @since 3.1.0
 */
@ConfigurationProperties(PasetoConfigurationProperties.PREFIX + ".shared-key-generator")
public class VersionedSharedSecretConfigurationProperties implements VersionedSharedSecretConfiguration {
    @NotNull
    @NonNull
    private Version version;

    @NonNull
    @NotNull
    private SecretKey sharedSecret;

    @Override
    @NonNull
    public Version getVersion() {
        return version;
    }

    /**
     *
     * @param version Paseto version
     */
    public void setVersion(@NonNull Version version) {
        this.version = version;
    }

    @Override
    @NonNull
    public SecretKey getSharedSecret() {
        return sharedSecret;
    }

    /**
     *
     * @param sharedSecret shared secret used for Paseto token
     */
    public void setSharedSecret(@NonNull SecretKey sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}
