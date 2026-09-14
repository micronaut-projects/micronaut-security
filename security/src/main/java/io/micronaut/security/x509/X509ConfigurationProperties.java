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
import io.micronaut.context.annotation.Context;
import org.jspecify.annotations.NonNull;
import io.micronaut.security.config.SecurityConfigurationProperties;
import jakarta.validation.constraints.NotBlank;

/**
 * Configuration for X.509 authentication.
 * The bean is created eagerly when the context starts so that an invalid {@code subject-dn-regex} fails the application startup.
 *
 * @author Burt Beckwith
 * @since 3.3
 */
@Context
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
     * The regex must contain exactly one capturing group, which is used to extract the name from the certificate subject DN.
     *
     * @param subjectDnRegex the regex
     * @throws io.micronaut.context.exceptions.ConfigurationException if the regex is not a valid regular expression with exactly one capturing group
     */
    public void setSubjectDnRegex(@NonNull String subjectDnRegex) {
        X509AuthenticationFetcher.compileSubjectDnRegex(subjectDnRegex);
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
