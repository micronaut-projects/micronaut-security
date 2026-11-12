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
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * Service-provider-assigned metadata common to SCIM resources.
 *
 * @param resourceType The resource type name
 * @param created The xsd:dateTime at which the resource was created
 * @param lastModified The xsd:dateTime at which the resource was last modified
 * @param location The URI of the resource
 * @param version The resource entity tag
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record Meta(
    @Nullable String resourceType,
    @Nullable String created,
    @Nullable String lastModified,
    @Nullable String location,
    @Nullable String version
) {
}
