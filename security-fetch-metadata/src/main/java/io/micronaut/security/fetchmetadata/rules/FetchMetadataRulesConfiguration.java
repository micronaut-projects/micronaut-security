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
package io.micronaut.security.fetchmetadata.rules;

/**
 * Configuration for the built-in Fetch Metadata rules.
 *
 * @since 5.4.0
 */
public interface FetchMetadataRulesConfiguration {
    /**
     * Whether requests to route-level CORS endpoints are allowed when the route's CORS
     * configuration permits the request origin and HTTP method.
     * Enabled by default.
     *
     * @return whether permitted cross-origin requests are allowed
     */
    boolean isAllowCrossOrigin();

    /**
     * Whether requests explicitly initiated by a user through browser UI are allowed.
     * These requests carry a {@code Sec-Fetch-Site} value of {@code none}.
     * Enabled by default.
     *
     * @return whether browser-initiated requests are allowed
     */
    boolean isAllowBrowserInitiatedRequests();

    /**
     * Whether requests from the same origin are allowed.
     * Enabled by default.
     *
     * @return whether same-origin requests are allowed
     */
    boolean isAllowSameOrigin();

    /**
     * Whether requests from another origin on the same site are allowed.
     * Applications should enable this only when every same-site origin is trusted.
     * Disabled by default.
     *
     * @return whether same-site requests are allowed
     */
    boolean isAllowSameSite();

    /**
     * Whether requests without a complete, valid set of Fetch Metadata headers are allowed.
     * Enabling this option supports clients that do not send Fetch Metadata, but those requests
     * must be protected by other controls such as CSRF protection and origin validation.
     * Enabled by default for compatibility with clients that do not send Fetch Metadata.
     *
     * @return whether requests without parsed Fetch Metadata are allowed
     */
    boolean isAllowNoFetchMetadata();
}
