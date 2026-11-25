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
import io.micronaut.security.scim.server.filter.ScimFilter;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import org.jspecify.annotations.Nullable;

/**
 * Persistence-neutral representation of RFC 7644 query parameters.
 *
 * @param attributes Response attribute selection
 * @param filter Parsed filter expression
 * @param filterExpression Original filter expression
 * @param sortBy Attribute path used for sorting
 * @param sortOrder Sort direction
 * @param startIndex One-based result index
 * @param count Maximum number of results requested
 * @since 5.4.0
 */
@Experimental
public record ScimQuery(
    ScimAttributeSelection attributes,
    @Nullable ScimFilter filter,
    @Nullable String filterExpression,
    @Nullable String sortBy,
    ScimSortOrder sortOrder,
    int startIndex,
    int count
) {
}
