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
package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.MediaType;
import io.micronaut.security.csrf.CsrfConfiguration;

import java.util.Set;

@Requires(classes = { HttpMethod.class, MediaType.class })
@Internal
@ConfigurationProperties(CsrfFilterConfigurationProperties.PREFIX)
final class CsrfFilterConfigurationProperties implements CsrfFilterConfiguration {
    public static final String PREFIX = CsrfConfiguration.PREFIX + ".filter";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default regex pattern.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String  DEFAULT_REGEX_PATTERN = "^.*$";

    private static final Set<HttpMethod> DEFAULT_METHODS = Set.of(
            HttpMethod.POST,
            HttpMethod.PUT,
            HttpMethod.DELETE,
            HttpMethod.PATCH
    );

    private static final Set<MediaType> DEFAULT_CONTENT_TYPES = Set.of(
            MediaType.APPLICATION_FORM_URLENCODED_TYPE,
            MediaType.MULTIPART_FORM_DATA_TYPE
    );
    private boolean enabled = DEFAULT_ENABLED;
    private String regexPattern = DEFAULT_REGEX_PATTERN;
    private Set<HttpMethod> methods = DEFAULT_METHODS;
    private Set<MediaType> contentTypes = DEFAULT_CONTENT_TYPES;

    @Override
    @NonNull
    public Set<HttpMethod> getMethods() {
        return methods;
    }

    /**
     *  Filter will only process requests whose method matches any of these methods. Default Value is POST, PUT, DELETE, PATCH.
     * @param methods HTTP methods.
     */
    public void setMethods(@NonNull Set<HttpMethod> methods) {
        this.methods = methods;
    }

    @Override
    @NonNull
    public Set<MediaType> getContentTypes() {
        return contentTypes;
    }

    /**
     * Filter will only process requests whose content type matches any of these content types. Default Value is application/x-www-form-urlencoded, multipart/form-data.
     * @param contentTypes Content Types
     */
    public void setContentTypes(@NonNull Set<MediaType> contentTypes) {
        this.contentTypes = contentTypes;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether the filter is enabled. Default value {@value #DEFAULT_ENABLED}.
     * @param enabled Whether the filter is enabled.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String getRegexPattern() {
        return regexPattern;
    }

    /**
     * CSRF filter processes only request paths matching this regular expression. Default Value: {@value #DEFAULT_REGEX_PATTERN}
     * @param regexPattern Regular expression pattern for the filter.
     */
    public void setRegexPattern(String regexPattern) {
        this.regexPattern = regexPattern;
    }
}
