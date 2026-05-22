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
package io.micronaut.security.token.propagation;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.util.OutgoingRequestProcessorMatcher;
import io.micronaut.security.token.config.TokenConfigurationProperties;

/**
 * Token Propagation Configuration Properties.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = OutgoingRequestProcessorMatcher.class)
@ConfigurationProperties(TokenPropagationConfigurationProperties.PREFIX)
public class TokenPropagationConfigurationProperties extends AbstractOutgoingRequestProcessorMatcher implements TokenPropagationConfiguration {

    public static final String PREFIX = TokenConfigurationProperties.PREFIX + ".propagation";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = false;

    /**
     * The default path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_PATH = "/**";

    private boolean enabled = DEFAULT_ENABLED;

    private String path = DEFAULT_PATH;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables {@link io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter}. Default value {@value #DEFAULT_ENABLED}
     * @param enabled enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Configures {@link io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter} path. Default value {@value #DEFAULT_PATH}
     * @param path Path to be matched by Token Propagation Filter.
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     *
     * @return Path to be matched by Token Propagation Filter.
     */
    @Override
    public String getPath() {
        return this.path;
    }

}
