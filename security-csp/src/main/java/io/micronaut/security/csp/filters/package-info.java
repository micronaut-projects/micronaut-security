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
 * HTTP server filter support for Content Security Policy response headers.
 *
 * <p>The package requires the {@code ResponseHeaderPopulator} API of the HTTP server, which writes
 * the header, so that the filter never generates nonces for responses that cannot carry the policy.</p>
 *
 * <p>Like every subpackage, it is also disabled by the {@code micronaut.security.csp.enabled}
 * requirement of the {@code io.micronaut.security.csp} package.</p>
 */
@NullMarked
@Requires(classes = {ServerFilter.class, ResponseHeaderPopulator.class})
@Requires(condition = CspFilterEnabledCondition.class)
@Configuration
package io.micronaut.security.csp.filters;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import org.jspecify.annotations.NullMarked;
