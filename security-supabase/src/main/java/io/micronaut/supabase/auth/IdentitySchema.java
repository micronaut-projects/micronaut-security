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
 * Identity linked to a Supabase Auth user.
 *
 * <p>A user has one identity per sign-in method, for example {@code email}, {@code phone} or an external
 * provider such as {@code github}. Identities can be linked and unlinked through
 * {@code /user/identities} when manual linking is enabled; a user must keep at least one identity.</p>
 *
 * @param identityId Unique identifier of the identity record
 * @param id Identifier of the user at the provider; equals the user id for the {@code email} and {@code phone}
 *           providers
 * @param userId Identifier of the Supabase Auth user the identity belongs to
 * @param identityData Profile data supplied by the provider, such as {@code email} and {@code sub}
 * @param provider Sign-in method, for example {@code email}, {@code phone} or {@code github}
 * @param lastSignInAt Timestamp of the last sign-in through this identity in RFC 3339 format
 * @param createdAt Creation timestamp in RFC 3339 format
 * @param updatedAt Last modification timestamp in RFC 3339 format
 * @param email Email address reported by the provider, if any
 * @since 0.0.1
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
