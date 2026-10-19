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
package io.micronaut.supabase;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Experimental;
import org.jspecify.annotations.Nullable;

/**
 * {@link SupabaseConfiguration} bound to the {@code supabase} configuration prefix.
 *
 * <pre>{@code
 * supabase:
 *   project-id: abcdefghijklmnopqrst
 *   auth-path: /auth/v1
 *   storage-path: /storage/v1
 *   publishable-key: sb_publishable_...
 *   secret-key: sb_secret_...
 * }</pre>
 *
 * <p>Set {@code supabase.url} instead of {@code supabase.project-id} for a custom domain.</p>
 *
 * @since 0.0.1
 */
@Experimental
@ConfigurationProperties(SupabaseConfigurationProperties.PREFIX)
public class SupabaseConfigurationProperties implements SupabaseConfiguration {

    /**
     * Configuration prefix.
     */
    public static final String PREFIX = "supabase";

    @Nullable
    private String url;

    @Nullable
    private String projectId;

    private String authPath = AUTH_PATH;

    private String storagePath = STORAGE_PATH;

    @Nullable
    private String publishableKey;

    @Nullable
    private String secretKey;

    /**
     * Creates the configuration with no keys set.
     */
    public SupabaseConfigurationProperties() {
    }

    @Override
    @Nullable
    public String getUrl() {
        return url;
    }

    /**
     * Sets the project URL, for example {@code https://abcdefgh.supabase.co} or a custom domain.
     *
     * @param url The project URL
     */
    public void setUrl(@Nullable String url) {
        this.url = url;
    }

    @Override
    @Nullable
    public String getProjectId() {
        return projectId;
    }

    /**
     * Sets the project identifier, the subdomain of a hosted project.
     *
     * @param projectId The project identifier
     */
    public void setProjectId(@Nullable String projectId) {
        this.projectId = projectId;
    }

    @Override
    public String getAuthPath() {
        return authPath;
    }

    /**
     * Sets the Auth API path below the project URL. Default value ({@value #AUTH_PATH}). Set it to an empty
     * string for a GoTrue server that serves the API at its root.
     *
     * @param authPath The Auth API path
     */
    public void setAuthPath(@Nullable String authPath) {
        this.authPath = authPath == null ? "" : authPath;
    }

    @Override
    public String getStoragePath() {
        return storagePath;
    }

    /**
     * Sets the Storage API path below the project URL. Default value ({@value #STORAGE_PATH}). Set it to an
     * empty string for a Storage API server that serves the API at its root.
     *
     * @param storagePath The Storage API path
     */
    public void setStoragePath(@Nullable String storagePath) {
        this.storagePath = storagePath == null ? "" : storagePath;
    }

    @Override
    @Nullable
    public String getPublishableKey() {
        return publishableKey;
    }

    /**
     * Sets the key sent on user-facing routes: a publishable key or a legacy anon key.
     *
     * @param publishableKey The publishable key
     */
    public void setPublishableKey(@Nullable String publishableKey) {
        this.publishableKey = publishableKey;
    }

    @Override
    @Nullable
    public String getSecretKey() {
        return secretKey;
    }

    /**
     * Sets the key sent on administrative routes: a secret key or a legacy service-role key.
     *
     * @param secretKey The secret key
     */
    public void setSecretKey(@Nullable String secretKey) {
        this.secretKey = secretKey;
    }
}
