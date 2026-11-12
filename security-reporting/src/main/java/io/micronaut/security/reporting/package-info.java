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
/**
 * Advertises named endpoints through the W3C Reporting API.
 *
 * <p>Each configured endpoint is serialized into the {@code Reporting-Endpoints} response header.
 * Browser features, including Content Security Policy, can reference those endpoint names when
 * routing reports. The package advertises endpoints; applications remain responsible for
 * implementing the endpoints and safely processing the reports they receive.</p>
 *
 * @see <a href="https://www.w3.org/TR/reporting-1/#header">Reporting-Endpoints response header</a>
 * @since 5.4.0
 */
@Configuration
@Requires(classes = ServerFilter.class)
@Requires(property = ReportingEndpointsFilterConfigurationProperties.PROPERTY_ENABLED, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@NullMarked
package io.micronaut.security.reporting;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.annotation.ServerFilter;
import org.jspecify.annotations.NullMarked;
