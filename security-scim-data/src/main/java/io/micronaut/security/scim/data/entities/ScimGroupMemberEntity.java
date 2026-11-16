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
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.Index;
import io.micronaut.data.annotation.MappedEntity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

/**
 * Persistent User or Group membership of an RFC 7643 Group.
 *
 * <p>The display value and reference URI are optional snapshots. Applications
 * may instead derive them from the referenced resource when producing a SCIM
 * response.</p>
 *
 * @param id The database-generated row identifier
 * @param groupId The owning Group identifier
 * @param memberId The referenced User or Group identifier
 * @param memberType The referenced resource type
 * @param referenceUri The URI of the referenced resource
 * @param display The human-readable display value
 * @since 5.4.0
 */
@MappedEntity("scim_group_member")
@Index(
    name = "scim_group_member_uk",
    columns = {"group_id", "member_id", "member_type"},
    unique = true
)
@Index(name = "scim_group_member_reverse_idx", columns = {"member_id", "member_type"})
@Experimental
public record ScimGroupMemberEntity(
    @Id @GeneratedValue @Nullable Long id,
    @NotBlank String groupId,
    @NotBlank String memberId,
    @NotNull ScimResourceType memberType,
    @Nullable String referenceUri,
    @Nullable String display
) {
}
