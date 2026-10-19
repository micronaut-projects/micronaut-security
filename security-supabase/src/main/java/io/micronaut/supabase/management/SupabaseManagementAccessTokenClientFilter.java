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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.ClientFilter;
import io.micronaut.http.annotation.RequestFilter;

/**
 * Sends the Management API access token as the bearer token of every request of the
 * {@code supabase-management} HTTP client.
 *
 * <p>Nothing is added when no {@linkplain SupabaseManagementConfiguration#getAccessToken() access token} is
 * configured or the request already carries an {@code Authorization} header, so a caller may authorize a
 * single request with a different token.</p>
 *
 * @since 0.0.1
 */
@Experimental
@ClientFilter(serviceId = SupabaseManagementConfiguration.SERVICE_ID)
@Requires(classes = ClientFilter.class)
@Requires(beans = SupabaseManagementConfiguration.class)
public class SupabaseManagementAccessTokenClientFilter {

    private final SupabaseManagementConfiguration configuration;

    /**
     * Creates the filter.
     *
     * @param configuration Management API credentials
     */
    public SupabaseManagementAccessTokenClientFilter(SupabaseManagementConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Adds the {@code Authorization} header with the configured access token.
     *
     * @param request Outgoing request
     */
    @RequestFilter
    public void filter(MutableHttpRequest<?> request) {
        String accessToken = configuration.getAccessToken();
        if (StringUtils.isNotEmpty(accessToken) && !request.getHeaders().contains(HttpHeaders.AUTHORIZATION)) {
            request.bearerAuth(accessToken);
        }
    }
}
