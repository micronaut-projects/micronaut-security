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
package io.micronaut.security.scim.server.model;

import io.micronaut.core.annotation.Experimental;

import java.util.List;

/**
 * Attributes explicitly included in or excluded from a SCIM response.
 *
 * @param attributes Requested attributes
 * @param excludedAttributes Attributes excluded from the default response set
 * @since 5.4.0
 */
@Experimental
public record ScimAttributeSelection(List<String> attributes, List<String> excludedAttributes) {
    /** No explicit attribute selection. */
    public static final ScimAttributeSelection ALL = new ScimAttributeSelection(List.of(), List.of());

    /**
     * Creates an immutable attribute selection.
     *
     * @since 5.4.0
     */
    public ScimAttributeSelection {
        attributes = List.copyOf(attributes);
        excludedAttributes = List.copyOf(excludedAttributes);
    }

    /**
     * @return Whether the client supplied an {@code attributes} parameter
     * @since 5.4.0
     */
    public boolean hasIncludedAttributes() {
        return !attributes.isEmpty();
    }
}
