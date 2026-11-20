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
package io.micronaut.security.fetchmetadata;

import io.micronaut.core.util.Toggleable;

/**
 * Configuration for the Fetch Metadata request filter.
 *
 * <p>The configuration bean only exists while the filter is enabled, so {@link #isEnabled()}
 * returns {@code true} for any injected instance. Use {@link #PROPERTY_ENABLED} with
 * {@code @Requires} to make a bean depend on whether the filter is enabled.</p>
 *
 * @since 5.6.0
 */
public interface FetchMetadataFilterConfiguration extends Toggleable {
    /** Configuration prefix for the Fetch Metadata request filter. */
    String PREFIX = "micronaut.security.fetch-metadata.filter";
    /** Property that enables or disables the Fetch Metadata request filter. */
    String PROPERTY_ENABLED = PREFIX + ".enabled";
    /** Property that sets the request path pattern the Fetch Metadata request filter applies to. */
    String PROPERTY_PATTERN = PREFIX + ".pattern";

    /**
     * Returns the request path pattern to which the Fetch Metadata filter applies.
     *
     * @return the pattern the {@link FetchMetadataFilter} should match
     */
    String getPattern();
}
