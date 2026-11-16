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
package io.micronaut.security.scim.server.protocol;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7644 POST {@code .search} request.
 *
 * @param schemas Message schema URIs
 * @param attributes Attributes to return
 * @param excludedAttributes Attributes not to return
 * @param filter Filter expression
 * @param sortBy Sort attribute path
 * @param sortOrder Sort direction
 * @param startIndex One-based start index
 * @param count Maximum page size
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimSearchRequest(
    @Nullable List<String> schemas,
    @Nullable List<String> attributes,
    @Nullable List<String> excludedAttributes,
    @Nullable String filter,
    @Nullable String sortBy,
    @Nullable ScimSortOrder sortOrder,
    @Nullable Integer startIndex,
    @Nullable Integer count
) {
}
