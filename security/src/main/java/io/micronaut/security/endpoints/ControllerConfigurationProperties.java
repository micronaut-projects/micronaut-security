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
package io.micronaut.security.endpoints;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MediaType;

import java.util.Set;

@Internal
abstract class ControllerConfigurationProperties implements ControllerConfiguration {
    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default supported content types for endpoints.
     */
    @SuppressWarnings("WeakerAccess")
    private static final Set<MediaType> DEFAULT_CONTENT_TYPES_FOR_POST_ENDPOINTS = Set.of(MediaType.APPLICATION_JSON_TYPE, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    private boolean enabled = DEFAULT_ENABLED;
    private String path;
    private Set<MediaType> postContentTypes = DEFAULT_CONTENT_TYPES_FOR_POST_ENDPOINTS;

    /**
     *
     * @param path The path where the controller is exposed.
     */
    ControllerConfigurationProperties(String path) {
        this.path = path;
    }

    @Override
    public Set<MediaType> getPostContentTypes() {
        return postContentTypes;
    }

    /**
     * Supported content types for POST endpoints. Default Value application/json and application/x-www-form-urlencoded
     * @param postContentTypes supported content types for POST endpoints.
     */
    public void setPostContentTypes(Set<MediaType> postContentTypes) {
        this.postContentTypes = postContentTypes;
    }

    /**
     * Whether the controller is enabled.
     * @return  Whether the controller is enabled.
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    @NonNull
    public String getPath() {
        return this.path;
    }

    /**
     * Enables the controller.
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Path to the controller.
     * @param path The path
     */
    public void setPath(String path) {
        if (StringUtils.isNotEmpty(path)) {
            this.path = path;
        }
    }
}
