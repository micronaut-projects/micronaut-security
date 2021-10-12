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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.token.paseto.config.PasetoConfigurationProperties;

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
    public static final String DEFAULT_TOKEN_TYPE = "local";

    /**
     * The default Paseto version. Possible values 1, 2.
     */
    public static final int DEFAULT_VERSION = 1;

    private String tokenType = DEFAULT_TOKEN_TYPE;
    private int version = DEFAULT_VERSION;

    /**
     * @return An integer indicating version of paseto
     */
    @Override
    public int getVersion() {
        return version;
    }

    /**
     * Sets Paseto version. Default value ({@value #DEFAULT_VERSION}).
     *
     * @param version Paseto version
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * @return return token type
     */
    @Override
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Sets Paseto token type. Default value ({@value #DEFAULT_TOKEN_TYPE})
     *
     * @param tokenType Paseto token type
     */
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

}
