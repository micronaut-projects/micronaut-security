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
package io.micronaut.security.scim.data.entities;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.data.annotation.DateCreated;
import io.micronaut.data.annotation.DateUpdated;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.Index;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.Version;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Persistent representation of an RFC 7643 Group resource.
 *
 * @param id The service-provider-assigned SCIM identifier
 * @param externalId The client-assigned identifier
 * @param displayName The human-readable group name
 * @param version The optimistic-lock version used to create the SCIM version value
 * @param created The resource creation time
 * @param lastModified The last modification time
 * @since 5.4.0
 */
@MappedEntity("scim_group")
@Index(name = "scim_group_external_id_idx", columns = "external_id")
@Experimental
public record ScimGroupEntity(
    @Id @NotBlank String id,
    @Nullable String externalId,
    @NotBlank String displayName,
    @Version @Nullable Long version,
    @DateCreated @Nullable Instant created,
    @DateUpdated @Nullable Instant lastModified
) {
}
