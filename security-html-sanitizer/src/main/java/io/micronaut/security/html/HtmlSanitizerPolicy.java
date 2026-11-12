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
package io.micronaut.security.html;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

/**
 * Supported OWASP HTML sanitizer policies.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public enum HtmlSanitizerPolicy {

    /**
     * Common block elements.
     */
    BLOCKS,

    /**
     * Common formatting elements.
     */
    FORMATTING,

    /**
     * Safe link elements and attributes.
     */
    LINKS,

    /**
     * Table elements.
     */
    TABLES,

    /**
     * Image elements and attributes.
     */
    IMAGES,

    /**
     * Inline style attributes.
     */
    STYLES;

    /**
     * The OWASP policy factory for this policy.
     *
     * @return The OWASP policy factory for this policy.
     */
    public PolicyFactory policyFactory() {
        return switch (this) {
            case BLOCKS -> Sanitizers.BLOCKS;
            case FORMATTING -> Sanitizers.FORMATTING;
            case LINKS -> Sanitizers.LINKS;
            case TABLES -> Sanitizers.TABLES;
            case IMAGES -> Sanitizers.IMAGES;
            case STYLES -> Sanitizers.STYLES;
        };
    }
}
