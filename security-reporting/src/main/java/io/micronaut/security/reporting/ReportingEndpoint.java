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
package io.micronaut.security.reporting;

import java.net.URI;

/**
 * A named endpoint to which user agents may deliver Reporting API reports.
 *
 * <p>The endpoint name is a Structured Fields dictionary key. Other response headers, such as
 * Content Security Policy, use that name to select an endpoint. The URL may be an absolute URI or
 * a relative URI reference, which the user agent resolves against the protected resource.</p>
 *
 * @since 5.4.0
 */
public interface ReportingEndpoint {
    /**
     * Returns the endpoint name referenced by reporting features.
     *
     * @return the Structured Fields dictionary key for this endpoint
     * @since 5.4.0
     */
    String getName();

    /**
     * Returns the URI reference to which reports are delivered.
     *
     * <p>The URI may be absolute or relative. A user agent resolves a relative URI against the
     * URL of the response carrying the {@code Reporting-Endpoints} header.</p>
     *
     * @return an absolute or relative reporting endpoint URI
     * @since 5.4.0
     */
    URI getUrl();
}
