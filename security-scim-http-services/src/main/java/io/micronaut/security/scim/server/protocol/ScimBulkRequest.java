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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7644 bulk request.
 *
 * @param schemas Message schema URIs
 * @param failOnErrors Number of errors accepted before stopping
 * @param operations Requested operations
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimBulkRequest(
    @Nullable List<String> schemas,
    @Nullable Integer failOnErrors,
    @Nullable @JsonProperty("Operations") List<ScimBulkRequestOperation> operations
) {
}
