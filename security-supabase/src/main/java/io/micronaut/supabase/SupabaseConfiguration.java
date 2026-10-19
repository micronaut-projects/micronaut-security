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

import io.micronaut.core.annotation.Experimental;
import org.jspecify.annotations.Nullable;

import java.util.Optional;

/**
 * Location and API keys of a Supabase project.
 *
 * <p>The project is addressed either by its URL or by its project identifier, from which the hosted URL is
 * derived. Supabase identifies the calling application with a key sent in the {@code apikey} header. Signed-in
 * users are identified separately by their access token in the {@code Authorization} header. Both keys are
 * optional: a self-hosted GoTrue server reached without the Supabase API gateway ignores the header.</p>
 *
 * <p>Current projects issue publishable keys ({@code sb_publishable_...}) and secret keys
 * ({@code sb_secret_...}), which are opaque strings. Legacy projects issue the anon and service-role keys,
 * which are JWTs starting with {@code eyJ}; both formats are accepted.</p>
 *
 * @since 0.0.1
 */
@Experimental
public interface SupabaseConfiguration {

    /**
     * Domain under which hosted projects are served, as {@code https://<project-id>.supabase.co}.
     */
    String HOSTED_DOMAIN = "supabase.co";

    /**
     * Default path of the Auth API below the project URL.
     */
    String AUTH_PATH = "/auth/v1";

    /**
     * Property holding the Auth API path, read by the {@code supabase} client as its context path.
     */
    String AUTH_PATH_PROPERTY = SupabaseConfigurationProperties.PREFIX + ".auth-path";

    /**
     * Default path of the Storage API below the project URL.
     */
    String STORAGE_PATH = "/storage/v1";

    /**
     * Property holding the Storage API path, read by the Storage client as its context path.
     */
    String STORAGE_PATH_PROPERTY = SupabaseConfigurationProperties.PREFIX + ".storage-path";

    /**
     * Project URL as shown in the Supabase dashboard, for example {@code https://abcdefgh.supabase.co} or a
     * custom domain. Takes precedence over {@link #getProjectId()}.
     *
     * @return The project URL, or {@code null} when none is configured
     */
    @Nullable
    String getUrl();

    /**
     * Project identifier, also called the project reference: the subdomain of a hosted project. Used to derive
     * the project URL when {@link #getUrl()} is not set.
     *
     * @return The project identifier, or {@code null} when none is configured
     */
    @Nullable
    String getProjectId();

    /**
     * Resolves the project URL: {@link #getUrl()} without a trailing slash when set, otherwise
     * {@code https://<project-id>.supabase.co} when {@link #getProjectId()} is set.
     *
     * @return The project URL, or empty when neither the URL nor the project identifier is configured
     */
    default Optional<String> getProjectUrl() {
        String url = getUrl();
        if (url != null && !url.isBlank()) {
            return Optional.of(url.endsWith("/") ? url.substring(0, url.length() - 1) : url);
        }
        String projectId = getProjectId();
        if (projectId != null && !projectId.isBlank()) {
            return Optional.of("https://" + projectId + "." + HOSTED_DOMAIN);
        }
        return Optional.empty();
    }

    /**
     * Path of the Auth API below the project URL. Hosted and self-hosted Supabase serve it at
     * {@value #AUTH_PATH}; a GoTrue server reached directly serves it at the root, configured as an empty path.
     *
     * @return The Auth API path
     */
    default String getAuthPath() {
        return AUTH_PATH;
    }

    /**
     * Resolves the Auth API base URL, the project URL followed by {@link #getAuthPath()}.
     *
     * @return The Auth API URL, or empty when the project URL cannot be resolved
     */
    default Optional<String> getAuthUrl() {
        return getProjectUrl().map(projectUrl -> projectUrl + getAuthPath());
    }

    /**
     * Path of the Storage API below the project URL. Hosted and self-hosted Supabase serve it at
     * {@value #STORAGE_PATH}; a Storage API server reached directly serves it at the root, configured as an
     * empty path.
     *
     * @return The Storage API path
     */
    default String getStoragePath() {
        return STORAGE_PATH;
    }

    /**
     * Resolves the Storage API base URL, the project URL followed by {@link #getStoragePath()}.
     *
     * @return The Storage API URL, or empty when the project URL cannot be resolved
     */
    default Optional<String> getStorageUrl() {
        return getProjectUrl().map(projectUrl -> projectUrl + getStoragePath());
    }

    /**
     * Key sent on user-facing routes. Safe to ship in browsers and mobile applications because access is
     * limited by Row Level Security: a publishable key, or a legacy anon key.
     *
     * @return The publishable key, or {@code null} when none is configured
     */
    @Nullable
    String getPublishableKey();

    /**
     * Key sent on administrative routes. Grants the {@code service_role} and bypasses Row Level Security, so
     * it must only be used from trusted backends: a secret key, or a legacy service-role key.
     *
     * @return The secret key, or {@code null} when none is configured
     */
    @Nullable
    String getSecretKey();
}
