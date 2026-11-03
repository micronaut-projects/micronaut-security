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
package io.micronaut.security.config;

import io.micronaut.context.annotation.ConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;

/**
 * {@link SignupRedirectConfiguration} read from {@code micronaut.security.redirect.signup.success} and
 * {@code micronaut.security.redirect.signup.failure}, next to the other redirect URLs.
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@ConfigurationProperties(SignupRedirectConfigurationProperties.PREFIX)
public class SignupRedirectConfigurationProperties implements SignupRedirectConfiguration {
    public static final String PREFIX = RedirectConfigurationProperties.PREFIX + ".signup";

    /**
     * The default signup success target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_SIGNUP_SUCCESS = "/";

    /**
     * The default signup failure target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_SIGNUP_FAILURE = "/";

    @NonNull
    @NotBlank
    private String success = DEFAULT_SIGNUP_SUCCESS;

    @NonNull
    @NotBlank
    private String failure = DEFAULT_SIGNUP_FAILURE;

    @Override
    @NonNull
    public String getSuccess() {
        return success;
    }

    /**
     * Where the user is redirected to after a successful signup. Default value ({@value #DEFAULT_SIGNUP_SUCCESS}).
     *
     * @param success The URL
     */
    public void setSuccess(@NonNull String success) {
        this.success = success;
    }

    @Override
    @NonNull
    public String getFailure() {
        return failure;
    }

    /**
     * Where the user is redirected to after a failed signup. Default value ({@value #DEFAULT_SIGNUP_FAILURE}).
     *
     * @param failure The URL
     */
    public void setFailure(@NonNull String failure) {
        this.failure = failure;
    }
}
