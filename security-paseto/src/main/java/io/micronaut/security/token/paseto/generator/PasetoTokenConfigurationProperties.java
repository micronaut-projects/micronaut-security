/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.generator;

import dev.paseto.jpaseto.Purpose;
import dev.paseto.jpaseto.Version;
import dev.paseto.jpaseto.lang.Keys;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.token.paseto.config.PasetoConfigurationProperties;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@ConfigurationProperties(PasetoTokenConfigurationProperties.PREFIX)
public class PasetoTokenConfigurationProperties implements PasetoTokenConfiguration {

    public static final String PREFIX = PasetoConfigurationProperties.PREFIX + "token";

    /**
     * The default token type. Possible values local, public.
     */
    public static final Purpose DEFAULT_PURPOSE = Purpose.PUBLIC;

    /**
     * The default Paseto version. Possible values 1, 2.
     */
    public static final Version DEFAULT_VERSION = Version.V1;

    /**
     * The default secret key.
     */
    public static final SecretKey DEFAULT_SECRET_KEY = null;

    private Purpose purpose = DEFAULT_PURPOSE;
    private Version version = DEFAULT_VERSION;
    private SecretKey secretKey = DEFAULT_SECRET_KEY;

    /**
     * @return An integer indicating version of paseto
     */
    @Override
    public Version getVersion() {
        return version;
    }

    /**
     * Sets Paseto version.
     *
     * @param version Paseto version
     */
    public void setVersion(String version) {
        this.version = Version.from(version);
    }

    /**
     * @return return token type
     */
    @Override
    public Purpose getPurpose() {
        return purpose;
    }

    /**
     * Sets Paseto token type.
     *
     * @param purpose Paseto token type
     */
    public void setPurpose(String purpose) {
        this.purpose = Purpose.from(purpose);
    }

    /**
     * @return return token type
     */
    @Override
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * Sets Secret key for Paseto token to encrypt with.
     *
     * @param secretKey Secret key for encryption
     */
    public void setSecretKey(String secretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        this.secretKey = Keys.secretKey(decodedKey);
    }

}
