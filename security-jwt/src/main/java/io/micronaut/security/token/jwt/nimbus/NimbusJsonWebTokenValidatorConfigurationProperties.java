/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.token.jwt.nimbus;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

/**
 * {@link ConfigurationProperties} implementation of {@link NimbusJsonWebTokenValidatorConfiguration}.
 * @author Sergio del Amo
 * @since 4.11.1
 */
@ConfigurationProperties(NimbusJsonWebTokenValidatorConfigurationProperties.PREFIX)
public class NimbusJsonWebTokenValidatorConfigurationProperties implements NimbusJsonWebTokenValidatorConfiguration {
    /**
     * The default reactive validator value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".nimbus";

    /**
     * The default reactive validator value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_REACTIVE_VALIDATOR = true;

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_VALIDATOR = true;

    private boolean reactiveValidator = DEFAULT_REACTIVE_VALIDATOR;
    private boolean validator = DEFAULT_VALIDATOR;

    @Override
    public boolean isReactiveValidator() {
        return reactiveValidator;
    }

    @Override
    public boolean isValidator() {
        return validator;
    }

    /**
     * Whether the bean {@link NimbusReactiveJsonWebTokenValidator} is enabled. Default value {@value #DEFAULT_REACTIVE_VALIDATOR}.
     * @param reactiveValidator Whether the bean {@link NimbusReactiveJsonWebTokenValidator} is enabled.
     */
    public void setReactiveValidator(boolean reactiveValidator) {
        this.reactiveValidator = reactiveValidator;
    }

    /**
     * Whether the bean {@link NimbusJsonWebTokenValidator} is enabled. Default value {@value #DEFAULT_VALIDATOR}.
     * @param validator Whether the bean {@link NimbusJsonWebTokenValidator} is enabled.
     */
    public void setValidator(boolean validator) {
        this.validator = validator;
    }
}
