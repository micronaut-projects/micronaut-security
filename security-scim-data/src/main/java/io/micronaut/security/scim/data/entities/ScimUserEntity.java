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
 * Persistent representation of an RFC 7643 User resource.
 *
 * <p>The core User schema URI is implied by the table. Group membership is
 * derived from {@link ScimGroupMemberEntity}; addresses, other multi-valued
 * attributes, and extensions are stored in their respective entities.</p>
 *
 * @param id The service-provider-assigned SCIM identifier
 * @param externalId The client-assigned identifier
 * @param userName The service-provider-unique user name
 * @param nameFormatted The complete formatted name
 * @param nameFamilyName The family name
 * @param nameGivenName The given name
 * @param nameMiddleName The middle name
 * @param nameHonorificPrefix The honorific prefix
 * @param nameHonorificSuffix The honorific suffix
 * @param displayName The primary display label
 * @param nickName The casual name
 * @param profileUrl The URI of the online profile
 * @param title The user's title
 * @param userType The user classification
 * @param preferredLanguage The preferred written or spoken language
 * @param locale The preferred locale
 * @param timezone The IANA time zone
 * @param active Whether the user can authenticate
 * @param version The optimistic-lock version used to create the SCIM version value
 * @param created The resource creation time
 * @param lastModified The last modification time
 * @since 5.4.0
 */
@MappedEntity("scim_user")
@Index(name = "scim_user_username_uk", columns = "user_name", unique = true)
@Index(name = "scim_user_external_id_idx", columns = "external_id")
@Experimental
public record ScimUserEntity(
    @Id @NotBlank String id,
    @Nullable String externalId,
    @NotBlank String userName,
    @Nullable String nameFormatted,
    @Nullable String nameFamilyName,
    @Nullable String nameGivenName,
    @Nullable String nameMiddleName,
    @Nullable String nameHonorificPrefix,
    @Nullable String nameHonorificSuffix,
    @Nullable String displayName,
    @Nullable String nickName,
    @Nullable String profileUrl,
    @Nullable String title,
    @Nullable String userType,
    @Nullable String preferredLanguage,
    @Nullable String locale,
    @Nullable String timezone,
    @Nullable Boolean active,
    @Version @Nullable Long version,
    @DateCreated @Nullable Instant created,
    @DateUpdated @Nullable Instant lastModified
) {
}
