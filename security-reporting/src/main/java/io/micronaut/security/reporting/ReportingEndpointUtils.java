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
import java.util.regex.Pattern;

/**
 * Decides whether a {@link ReportingEndpoint} can be serialized into the
 * {@code Reporting-Endpoints} header.
 *
 * <p>The header is a Structured Fields dictionary
 * (<a href="https://www.rfc-editor.org/rfc/rfc8941#section-3.1.2">RFC 8941, Section 3.1.2</a>),
 * whose keys must match {@code [a-z*][a-z0-9_\-.*]*}. A key outside that grammar makes user
 * agents discard the whole header, and an endpoint without a URL leaves nothing to serialize, so
 * both are rejected before a header is rendered.</p>
 *
 * @since 5.6.0
 */
@Internal
final class ReportingEndpointUtils {
    /** The RFC 8941 {@code sf-key} grammar as a regular expression. */
    static final String KEY_GRAMMAR = "[a-z*][a-z0-9_\\-.*]*";

    private static final Pattern KEY_PATTERN = Pattern.compile(KEY_GRAMMAR);

    private ReportingEndpointUtils() {
    }

    /**
     * Reports whether an endpoint has both a valid name and a URL.
     *
     * @param endpoint candidate endpoint
     * @return {@code true} when the endpoint can be serialized
     */
    static boolean isValid(@Nullable ReportingEndpoint endpoint) {
        // Implementations outside this module, and configuration entries without a url, can
        // return null even though the contract is non-null.
        return endpoint != null && isValidName(endpoint.getName()) && isValidUrl(endpoint.getUrl());
    }

    /**
     * Reports whether a name is a valid Structured Fields dictionary key.
     *
     * @param name candidate endpoint name
     * @return {@code true} when the name matches {@value #KEY_GRAMMAR}
     */
    static boolean isValidName(@Nullable String name) {
        return name != null && KEY_PATTERN.matcher(name).matches();
    }

    /**
     * Reports whether an endpoint URL is present and not empty.
     *
     * @param url candidate endpoint URL
     * @return {@code true} when the URL can be serialized
     */
    static boolean isValidUrl(@Nullable URI url) {
        return url != null && !url.toString().isEmpty();
    }

    /**
     * Rejects a name or URL that cannot be serialized.
     *
     * @param name candidate endpoint name
     * @param url candidate endpoint URL
     * @throws IllegalArgumentException when the name does not match {@value #KEY_GRAMMAR}, or
     * the URL is missing or empty
     */
    static void require(@Nullable String name, @Nullable URI url) {
        if (!isValidName(name)) {
            throw new IllegalArgumentException(describeInvalidName(name));
        }
        if (!isValidUrl(url)) {
            throw new IllegalArgumentException("Reporting endpoint \"" + name + "\" has no URL");
        }
    }

    /**
     * Builds the message explaining why a name is not a valid endpoint name.
     *
     * @param name rejected endpoint name
     * @return a message naming the rejected value and the accepted grammar
     */
    static String describeInvalidName(@Nullable String name) {
        return "Reporting endpoint name \"" + name + "\" is not a valid Structured Fields dictionary key"
            + " (RFC 8941); it must match " + KEY_GRAMMAR;
    }
}
