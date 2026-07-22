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
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

/**
 * Persistent representation of the RFC 7643 Enterprise User extension.
 *
 * <p>The presence of a row indicates that the Enterprise User schema URI must
 * be included in the User resource's {@code schemas} array.</p>
 *
 * @param userId The owning User identifier and primary key
 * @param employeeNumber The organization-assigned employee number
 * @param costCenter The cost center
 * @param organization The organization name
 * @param division The organization division
 * @param department The organization department
 * @param managerValue The manager's User identifier
 * @param managerReferenceUri The URI of the manager's User resource
 * @param managerDisplayName The manager's display name
 * @since 5.4.0
 */
@MappedEntity("scim_enterprise_user")
@Experimental
public record ScimEnterpriseUserEntity(
    @Id @NotBlank String userId,
    @Nullable String employeeNumber,
    @Nullable String costCenter,
    @Nullable String organization,
    @Nullable String division,
    @Nullable String department,
    @Nullable String managerValue,
    @Nullable String managerReferenceUri,
    @Nullable String managerDisplayName
) {
}
