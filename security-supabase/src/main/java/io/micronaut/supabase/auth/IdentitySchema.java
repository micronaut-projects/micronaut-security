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
package io.micronaut.supabase.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;
import java.util.Map;

/**
 * Models the IdentitySchema object in Supabase Auth.
 *
 * @param identityId The value for {@code identityId}.
 * @param id The value for {@code id}.
 * @param userId The value for {@code userId}.
 * @param identityData The value for {@code identityData}.
 * @param provider The value for {@code provider}.
 * @param lastSignInAt The value for {@code lastSignInAt}.
 * @param createdAt The value for {@code createdAt}.
 * @param updatedAt The value for {@code updatedAt}.
 * @param email The value for {@code email}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record IdentitySchema(
    @JsonProperty("identity_id") @Nullable String identityId,
    @Nullable String id,
    @JsonProperty("user_id") @Nullable String userId,
    @JsonProperty("identity_data") @Nullable Map<String, Object> identityData,
    @Nullable String provider,
    @JsonProperty("last_sign_in_at") @Nullable String lastSignInAt,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt,
    @Nullable String email
) {
}
