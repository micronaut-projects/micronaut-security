/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.x509;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.config.SecurityConfigurationProperties;

import javax.validation.constraints.NotBlank;

/**
 * Configuration for X.509 authentication.
 *
 * @author Burt Beckwith
 * @since 3.3
 */
@ConfigurationProperties(X509ConfigurationProperties.PREFIX)
public class X509ConfigurationProperties implements X509Configuration {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".x509";

    /**
     * The default enabled value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = false;

    /**
     * The default Subject Distinguished Name (DN) regex.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_SUBJECT_DN_REGEX = "CN=(.*?)(?:,|$)";

    private boolean enabled = DEFAULT_ENABLED;

    @NonNull
    @NotBlank
    private String subjectDnRegex = DEFAULT_SUBJECT_DN_REGEX;

    @NonNull
    @Override
    public String getSubjectDnRegex() {
        return subjectDnRegex;
    }

    /**
     * Set the Subject DN regex. Default value {@value #DEFAULT_SUBJECT_DN_REGEX}.
     *
     * @param subjectDnRegex the regex
     */
    public void setSubjectDnRegex(@NonNull String subjectDnRegex) {
        this.subjectDnRegex = subjectDnRegex;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables the {@link X509AuthenticationFetcher}. Default value {@value #DEFAULT_ENABLED}.
     *
     * @param enabled true if enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
