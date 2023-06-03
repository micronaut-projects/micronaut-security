/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.filters;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.management.endpoint.EndpointsFilter;

/**
 * Replaces the {@link EndpointsFilter} with a dummy implementation. The {@link io.micronaut.security.rules.SensitiveEndpointRule} manages the sensitivity of endpoints.
 * @author Sergio del Amo
 * @since 4.0.0
 */
@Requires(property = SecurityFilterConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ServerFilter(Filter.MATCH_ALL_PATTERN)
@Replaces(EndpointsFilter.class)
@Internal
public class EndpointsFilterReplacement extends EndpointsFilter {
    /**
     * Constructor.
     *
     * @param endpointSensitivityProcessor The processor that resolves endpoint sensitivity
     */
    public EndpointsFilterReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor) {
        super(endpointSensitivityProcessor);
    }

    @Override
    @RequestFilter
    @Nullable
    public HttpResponse<?> doFilter(HttpRequest<?> request) {
        return null;
    }
}
