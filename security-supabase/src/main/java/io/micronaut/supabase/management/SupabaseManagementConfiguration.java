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

import io.micronaut.core.annotation.Experimental;
import org.jspecify.annotations.Nullable;

/**
 * Location and credentials of the Supabase Management API.
 *
 * <p>The Management API is authorized by a bearer token: a personal access token generated in the Supabase
 * dashboard, or an access token obtained by a Supabase OAuth application. Both grant access to every project
 * the token owner can administer, so they must only be used from trusted backends.</p>
 *
 * @since 0.0.1
 */
@Experimental
public interface SupabaseManagementConfiguration {

    /**
     * Service id of the Management API HTTP clients, configured under
     * {@code micronaut.http.services.supabase-management}.
     */
    String SERVICE_ID = "supabase-management";

    /**
     * URL of the hosted Management API.
     */
    String DEFAULT_URL = "https://api.supabase.com";

    /**
     * URL of the Management API without a trailing slash. Defaults to {@value #DEFAULT_URL}.
     *
     * @return The Management API URL
     */
    default String getUrl() {
        return DEFAULT_URL;
    }

    /**
     * Token sent as the bearer token of every Management API request: a personal access token or an OAuth
     * access token.
     *
     * @return The access token, or {@code null} when none is configured
     */
    @Nullable
    String getAccessToken();
}
