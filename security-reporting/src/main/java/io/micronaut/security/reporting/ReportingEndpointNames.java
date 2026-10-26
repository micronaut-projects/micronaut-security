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

import java.util.regex.Pattern;

/**
 * Validates Reporting API endpoint names against the Structured Fields dictionary-key grammar.
 *
 * <p>The {@code Reporting-Endpoints} header is a Structured Fields dictionary
 * (<a href="https://www.rfc-editor.org/rfc/rfc8941#section-3.1.2">RFC 8941, Section 3.1.2</a>),
 * whose keys must match {@code [a-z*][a-z0-9_\-.*]*}. A key outside that grammar makes user
 * agents discard the whole header, so names are rejected before a header is rendered.</p>
 *
 * @since 5.4.0
 */
@Internal
final class ReportingEndpointNames {
    /** The RFC 8941 {@code sf-key} grammar as a regular expression. */
    static final String KEY_GRAMMAR = "[a-z*][a-z0-9_\\-.*]*";

    private static final Pattern KEY_PATTERN = Pattern.compile(KEY_GRAMMAR);

    private ReportingEndpointNames() {
    }

    /**
     * Reports whether a name is a valid Structured Fields dictionary key.
     *
     * @param name candidate endpoint name
     * @return {@code true} when the name matches {@value #KEY_GRAMMAR}
     */
    static boolean isValid(@Nullable String name) {
        return name != null && KEY_PATTERN.matcher(name).matches();
    }

    /**
     * Returns the name when it is a valid Structured Fields dictionary key.
     *
     * @param name candidate endpoint name
     * @return the validated name
     * @throws IllegalArgumentException when the name does not match {@value #KEY_GRAMMAR}
     */
    static String require(@Nullable String name) {
        if (!isValid(name)) {
            throw new IllegalArgumentException(describeInvalid(name));
        }
        return name;
    }

    /**
     * Builds the message explaining why a name is not a valid endpoint name.
     *
     * @param name rejected endpoint name
     * @return a message naming the rejected value and the accepted grammar
     */
    static String describeInvalid(@Nullable String name) {
        return "Reporting endpoint name \"" + name + "\" is not a valid Structured Fields dictionary key"
            + " (RFC 8941); it must match " + KEY_GRAMMAR;
    }
}
