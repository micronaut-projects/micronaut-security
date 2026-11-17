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

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;

import java.net.URI;

/**
 * Decides whether a {@link ReportingEndpoint} can be serialized into the
 * {@code Reporting-Endpoints} header.
 *
 * @since 5.6.0
 */
@Internal
final class ReportingEndpointUtils {
    private ReportingEndpointUtils() {
    }

    /**
     * Reports whether an endpoint has both a valid name and a URL.
     *
     * <p>The name must be a Structured Fields dictionary key (RFC 8941) and the URL must be
     * present and not empty. An endpoint failing either check cannot be advertised: an invalid
     * name makes user agents discard the whole header, and a missing URL leaves nothing to
     * serialize.</p>
     *
     * @param endpoint candidate endpoint
     * @return {@code true} when the endpoint can be serialized
     */
    static boolean isValid(@Nullable ReportingEndpoint endpoint) {
        if (endpoint == null || !ReportingEndpointNames.isValid(endpoint.getName())) {
            return false;
        }
        // Implementations outside this module, and configuration entries without a url, can
        // return null even though the contract is non-null.
        @Nullable URI url = endpoint.getUrl();
        return url != null && !url.toString().isEmpty();
    }
}
