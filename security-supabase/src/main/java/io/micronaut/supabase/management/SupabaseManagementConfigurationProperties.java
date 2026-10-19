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
package io.micronaut.supabase.management;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.util.StringUtils;
import org.jspecify.annotations.Nullable;

/**
 * {@link SupabaseManagementConfiguration} bound to the {@code supabase.management} configuration prefix.
 *
 * <pre>{@code
 * supabase:
 *   management:
 *     access-token: sbp_...
 * }</pre>
 *
 * <p>Set {@code supabase.management.url} to address a Management API other than the hosted one.</p>
 *
 * @since 0.0.1
 */
@Experimental
@ConfigurationProperties(SupabaseManagementConfigurationProperties.PREFIX)
public class SupabaseManagementConfigurationProperties implements SupabaseManagementConfiguration {

    /**
     * Configuration prefix.
     */
    public static final String PREFIX = "supabase.management";

    private String url = DEFAULT_URL;

    @Nullable
    private String accessToken;

    /**
     * Creates the configuration addressing the hosted Management API with no access token set.
     */
    public SupabaseManagementConfigurationProperties() {
    }

    @Override
    public String getUrl() {
        return url;
    }

    /**
     * Sets the Management API URL. Default value ({@value #DEFAULT_URL}). A trailing slash is removed, and a
     * null or blank value restores the default.
     *
     * @param url The Management API URL
     */
    public void setUrl(@Nullable String url) {
        if (StringUtils.isEmpty(url) || url.isBlank()) {
            this.url = DEFAULT_URL;
        } else {
            this.url = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        }
    }

    @Override
    @Nullable
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Sets the token sent as the bearer token of every Management API request.
     *
     * @param accessToken The personal access token or OAuth access token
     */
    public void setAccessToken(@Nullable String accessToken) {
        this.accessToken = accessToken;
    }
}
