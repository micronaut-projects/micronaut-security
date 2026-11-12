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
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

/**
 * Persistent entry in the RFC 7643 multi-valued User {@code addresses} attribute.
 *
 * @param id The database-generated row identifier
 * @param userId The owning User identifier
 * @param formatted The full mailing address
 * @param streetAddress The street address component
 * @param locality The city or locality
 * @param region The state or region
 * @param postalCode The postal code
 * @param country The ISO 3166-1 alpha-2 country code
 * @param type The address type, such as {@code work} or {@code home}
 * @param primaryValue Whether this is the primary address
 * @param position The stable position used when reconstructing the SCIM array
 * @since 5.4.0
 */
@MappedEntity("scim_user_address")
@Index(name = "scim_user_address_owner_idx", columns = "user_id")
@Experimental
public record ScimUserAddressEntity(
    @Id @GeneratedValue @Nullable Long id,
    @NotBlank String userId,
    @Nullable String formatted,
    @Nullable String streetAddress,
    @Nullable String locality,
    @Nullable String region,
    @Nullable String postalCode,
    @Nullable String country,
    @Nullable String type,
    @Nullable Boolean primaryValue,
    @Min(0) int position
) {
}
