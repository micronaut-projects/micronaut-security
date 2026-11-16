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
 * A page returned by an application persistence implementation.
 *
 * @param resources Resources in this page
 * @param totalResults Total matching resources before pagination
 * @param startIndex One-based index of the first returned resource
 * @param <T> Resource type
 * @since 5.4.0
 */
@Experimental
public record ScimPage<T>(List<T> resources, long totalResults, int startIndex) {
    /**
     * Creates an immutable, validated result page.
     *
     * @since 5.4.0
     */
    public ScimPage {
        resources = List.copyOf(resources);
        if (totalResults < 0) {
            throw new IllegalArgumentException("totalResults must not be negative");
        }
        if (startIndex < 1) {
            throw new IllegalArgumentException("startIndex must be at least 1");
        }
    }
}
